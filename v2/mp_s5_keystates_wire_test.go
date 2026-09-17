package tdnsmp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// S5's second half on the wire (tdns-mp #58): a provider's DNSKEY REPLACE
// carries what it says about each key; the receiving agent hands the
// zone's complete latest set to its signer; the signer's machine writes ds
// on the foreign rows.

func invItem(t *testing.T, zone string, flags uint16, state string, ds *bool) KeyInventoryItem {
	t.Helper()
	k := testDnskey(t, zone, flags)
	return KeyInventoryItem{KeyTag: k.KeyTag(), Algorithm: k.Algorithm, Flags: flags, State: state, KeyRR: k.String(), Pub: true, DS: ds}
}

// The sender: the key states come from the signer's inventory, own served
// keys only, and a change of state or ds with the key set as it was is a
// change to send.
func TestLocalKeyStatesTravelWithTheDnskeys(t *testing.T) {
	yes, no := true, false
	mpzd := signerTestZone(t, "states.wire.example.", newMPTestKeyDB(t))
	ksk := invItem(t, mpzd.ZoneName, 257, KeyStateActive, &yes)
	zsk := invItem(t, mpzd.ZoneName, 256, KeyStateActive, &no)
	next := invItem(t, mpzd.ZoneName, 257, KeyStatePublished, &no)
	theirs := invItem(t, mpzd.ZoneName, 257, DnskeyStateForeign, nil)
	minted := invItem(t, mpzd.ZoneName, 256, KeyStateCreated, &no)
	inventory := func(items ...KeyInventoryItem) {
		mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: mpzd.ZoneName, Inventory: items, Received: time.Now()})
	}
	inventory(ksk, zsk, next, theirs, minted)
	changed, ds, err := mpzd.LocalDnskeysFromKeystate()
	if err != nil || !changed || ds == nil {
		t.Fatalf("the first inventory: changed=%v err=%v", changed, err)
	}
	if len(ds.CurrentKeyStates) != 3 || !ds.StatesChanged {
		t.Fatalf("key states %+v (changed=%v), want our three served keys", ds.CurrentKeyStates, ds.StatesChanged)
	}
	byTag := map[uint16]core.KeyState{}
	for i, st := range ds.CurrentKeyStates {
		byTag[st.KeyTag] = st
		if i > 0 && ds.CurrentKeyStates[i-1].KeyTag > st.KeyTag {
			t.Error("the key states are not in key tag order")
		}
	}
	if st := byTag[ksk.KeyTag]; st.State != KeyStateActive || st.DS == nil || !*st.DS {
		t.Errorf("the active KSK travels as %+v", st)
	}
	if st := byTag[next.KeyTag]; st.State != KeyStatePublished || st.DS == nil || *st.DS {
		t.Errorf("the published KSK travels as %+v", st)
	}
	if _, there := byTag[theirs.KeyTag]; there {
		t.Error("another provider's key is among what we say about ours")
	}
	// the same inventory again: nothing to send
	if changed, ds, _ := mpzd.LocalDnskeysFromKeystate(); changed || ds.StatesChanged {
		t.Errorf("the same inventory again: changed=%v states changed=%v", changed, ds.StatesChanged)
	}
	// the published KSK becomes standby with its ds set: the key set is as
	// it was, and it is a change to send all the same
	next.State, next.DS = KeyStateStandby, &yes
	inventory(ksk, zsk, next, theirs, minted)
	changed, ds, _ = mpzd.LocalDnskeysFromKeystate()
	if !changed || !ds.StatesChanged || len(ds.LocalAdds)+len(ds.LocalRemoves) != 0 {
		t.Errorf("a state and ds change alone: changed=%v states changed=%v adds=%d removes=%d", changed, ds.StatesChanged, len(ds.LocalAdds), len(ds.LocalRemoves))
	}
	// a row whose ds nobody decided travels undecided
	zsk.DS = nil
	inventory(ksk, zsk, next, theirs, minted)
	_, ds, _ = mpzd.LocalDnskeysFromKeystate()
	for _, st := range ds.CurrentKeyStates {
		if st.KeyTag == zsk.KeyTag && st.DS != nil {
			t.Errorf("an undecided ds travels as %v", *st.DS)
		}
	}
}

// The REPLACE the agent sends carries the key states, and a states-only
// change is marked so the engine sends it on though no record changed.
func TestDnskeySyncCarriesTheKeyStates(t *testing.T) {
	yes := true
	mpzd := signerTestZone(t, "sync.wire.example.", newMPTestKeyDB(t))
	k := testDnskey(t, mpzd.ZoneName, 257)
	q := make(chan *SynchedDataUpdate, 1)
	status := &DnskeyStatus{Time: time.Now(), ZoneName: mpzd.ZoneName, CurrentLocalKeys: []dns.RR{k},
		CurrentKeyStates: []core.KeyState{{KeyTag: k.KeyTag(), State: KeyStateStandby, DS: &yes}}, StatesChanged: true}
	(&AgentRegistry{}).SyncRequestHandler("agent.us.example.", SyncRequest{Command: "SYNC-DNSKEY-RRSET", ZoneName: ZoneName(mpzd.ZoneName), DnskeyStatus: status}, q, nil)
	select {
	case u := <-q:
		if !u.KeyStatesChanged || len(u.DnskeyKeyTags) != 0 {
			t.Errorf("a states-only change: KeyStatesChanged=%v tracked key tags %v", u.KeyStatesChanged, u.DnskeyKeyTags)
		}
		if len(u.Update.Operations) != 1 || len(u.Update.Operations[0].KeyStates) != 1 || u.Update.Operations[0].KeyStates[0].State != KeyStateStandby {
			t.Errorf("the operation sent: %+v", u.Update.Operations)
		}
	default:
		t.Fatal("a states-only change was not sent on")
	}
	// nothing changed at all: nothing is sent
	status.StatesChanged = false
	(&AgentRegistry{}).SyncRequestHandler("agent.us.example.", SyncRequest{Command: "SYNC-DNSKEY-RRSET", ZoneName: ZoneName(mpzd.ZoneName), DnskeyStatus: status}, q, nil)
	select {
	case u := <-q:
		t.Errorf("no change at all was sent on: %+v", u)
	default:
	}
}

// The join, end to end without a network: the sender's operation as JSON,
// the receiving agent's record and hand-over, the KEYSTATE "foreign" as it
// travels to the signer, the signer's routing, the engine, the row.
func TestForeignKeyStatesReachTheRowThroughTheRealPath(t *testing.T) {
	yes := true
	mpzd := trackTestZone(t, "join.wire.example.") // signed by us and p2; p3 does not sign
	kdb := mpzd.KeyDB
	theirs, outsiders := testDnskey(t, mpzd.ZoneName, 257), testDnskey(t, mpzd.ZoneName, 257)
	for _, k := range []*dns.DNSKEY{theirs, outsiders} {
		if err := insertForeignKeyRow(kdb, mpzd.ZoneName, k.KeyTag(), k, "ED25519"); err != nil {
			t.Fatal(err)
		}
	}
	// the sending providers' operations, over the wire's JSON
	wire := func(kt uint16) []core.RROperation {
		b, err := json.Marshal([]core.RROperation{{Operation: "replace", RRtype: "DNSKEY", KeyStates: []core.KeyState{{KeyTag: kt, State: KeyStateActive, DS: &yes}}}})
		if err != nil {
			t.Fatal(err)
		}
		var ops []core.RROperation
		if err := json.Unmarshal(b, &ops); err != nil {
			t.Fatal(err)
		}
		return ops
	}
	agent := &MPTransportBridge{}
	agent.NoteForeignKeyStates(ZoneName(mpzd.ZoneName), "agent.p2.example.", wire(theirs.KeyTag()))
	agent.NoteForeignKeyStates(ZoneName(mpzd.ZoneName), "agent.p3.example.", wire(outsiders.KeyTag()))
	// an older release's operation says nothing, and takes nothing back
	agent.NoteForeignKeyStates(ZoneName(mpzd.ZoneName), "agent.p2.example.", []core.RROperation{{Operation: "replace", RRtype: "DNSKEY"}})
	keys := agent.foreignKeysFor(ZoneName(mpzd.ZoneName))
	if len(keys) != 2 || keys[0].Provider != "p2" || keys[1].Provider != "p3" {
		t.Fatalf("what the agent hands its signer: %+v, want p2's and p3's key with their labels", keys)
	}
	// agent -> signer, as the message travels
	msg, err := keystateAppMessage(&PeerKeystateRequest{SenderID: "agent.us.example.", Zone: mpzd.ZoneName, Signal: "foreign", ForeignKeys: keys, Timestamp: time.Now()}, "signer.us.example.")
	if err != nil {
		t.Fatal(err)
	}
	signer := &MPTransportBridge{msgQs: &MsgQs{KeystateSignal: make(chan *KeystateSignalMsg, 1)}}
	signer.routeKeystateMessage(&transport.IncomingMessage{TypeToken: "keystate", Zone: mpzd.ZoneName, Payload: msg.Payload})
	var sig *KeystateSignalMsg
	select {
	case sig = <-signer.msgQs.KeystateSignal:
	default:
		t.Fatal("the signer's routing dropped the foreign key states")
	}
	if sig.Signal != "foreign" || len(sig.ForeignKeys) != 2 {
		t.Fatalf("what reached the signer's handler: %+v", sig)
	}
	// the signer's engine and the zone's driver
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "signer", Agents: []*PeerConf{{Identity: "agent.us.example."}}, KeyLifecycleZones: []string{mpzd.ZoneName}})
	conf.Config.Internal.KeyDB = kdb
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
	e := NewKeyLifecycleEngine(conf, owner)
	e.TakeConfiguredZones()
	if !e.Foreign(sig.Zone, sig.ForeignKeys) {
		t.Fatal("the engine does not take the zone for its own")
	}
	cols := func(kt uint16) string {
		f, err := e.driver(mpzd.ZoneName).columnsOf(kt)
		if err != nil {
			t.Fatal(err)
		}
		return flagsOf(f)
	}
	if got := cols(theirs.KeyTag()); got != "101" {
		t.Errorf("the signing provider's active KSK: columns %s, want 101", got)
	}
	if got := cols(outsiders.KeyTag()); got != "100" {
		t.Errorf("the key of a provider that does not sign: columns %s, want 100", got)
	}
	// a zone nobody here owns: the word has no reader
	if e.Foreign("unowned.wire.example.", sig.ForeignKeys) {
		t.Error("the engine claimed the key states of a zone it does not own")
	}
}
