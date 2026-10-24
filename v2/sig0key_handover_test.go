/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// handoverZone is a zone whose providers all transfer it from the owner: no
// agent is another's upstream or downstream. alice and bob have voting roles,
// carol audits, and dave has an HSYNC3 record and no role.
func handoverZone(t *testing.T, zone string) *tdns.ZoneData {
	t.Helper()
	zd := seedZoneWithHSYNC3(t, zone, "alice.agent.example.", "bob.agent.example.", "carol.agent.example.", "dave.agent.example.")
	rr, err := dns.NewRR(zone + ` 3600 IN HSYNCPARAM servers="alice" signers="bob" auditors="carol"`)
	if err != nil {
		t.Fatalf("HSYNCPARAM: %v", err)
	}
	apex, _ := zd.Data.Get(zone)
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{rr}})
	zd.Data.Set(zone, apex)
	zd.InstallInitialSnapshot()
	return zd
}

// The zone's SIG(0) key is the provider group's: any agent that can be
// elected the zone's leader may hold it. It went only to an agent's upstream
// or downstream, which say who transfers the zone from whom, so in a zone
// like this one no agent got it, and every new leader made a key of its own.
func TestTheZoneKeyGoesToAnyAgentThatCanLead(t *testing.T) {
	const zone = "handover.example."
	handoverZone(t, zone)
	for agent, want := range map[AgentId]bool{
		"alice.agent.example.": true,  // servers
		"bob.agent.example.":   true,  // signers
		"alice.agent.example":  true,  // the same, as a configured identity without the trailing dot
		"carol.agent.example.": false, // auditors: no vote, never leads
		"dave.agent.example.":  false, // no role
		"eve.agent.example.":   false, // not in the zone
	} {
		if got := mayHoldZoneSig0Key(zone, agent); got != want {
			t.Errorf("%s may hold the zone's key: %v, want %v", agent, got, want)
		}
	}
}

type keyAnswer struct {
	requester, subtype, nonce string
	data                      map[string]string
}

// The agent that holds the key answers a CONFIG sig0key request from an agent
// that can lead with the key, and any other with a refusal. The refusal is an
// answer: the asker waits for one, and without it waited out its timeout.
func TestTheKeyHolderAnswersEveryKeyRequest(t *testing.T) {
	const zone = "answered.example."
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true})
	zd := handoverZone(t, zone)
	zd.KeyDB = newMPTestKeyDB(t)
	if _, err := zd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: zone,
		Keyname: zone, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	answers := make(chan keyAnswer, 4)
	saved := answerConfigRequest
	answerConfigRequest = func(_ *MPTransportBridge, _ *AgentRegistry, requester, _, subtype, nonce, _ string, data map[string]string) {
		answers <- keyAnswer{requester, subtype, nonce, data}
	}
	t.Cleanup(func() { answerConfigRequest = saved })

	ask := func(from string) keyAnswer {
		t.Helper()
		env.Bob.Registry.MsgHandler(&AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{MessageType: AgentMsgRfi,
			OriginatorID: AgentId(from), Zone: zone, RfiType: "CONFIG", RfiSubtype: "sig0key", Nonce: "nonce-" + from}}, nil, nil)
		select {
		case a := <-answers:
			if a.requester != from || a.subtype != "sig0key" || a.nonce != "nonce-"+from {
				t.Errorf("the answer to %s: %+v", from, a)
			}
			return a
		case <-time.After(5 * time.Second):
			t.Fatalf("%s's request got no answer", from)
			return keyAnswer{}
		}
	}

	for _, from := range []string{"alice.agent.example.", "bob.agent.example"} {
		a := ask(from)
		if a.data["privatekey"] == "" || a.data["keyrr"] == "" || a.data[configRefusedKey] != "" {
			t.Errorf("%s, which can lead, did not get the key: %v", from, a.data)
		}
	}
	for _, from := range []string{"carol.agent.example.", "dave.agent.example."} {
		a := ask(from)
		if a.data["privatekey"] != "" {
			t.Errorf("%s, which cannot lead, got the key", from)
		}
		resp := &ConfigResponseMsg{ConfigData: a.data}
		if why := resp.Refused(); !strings.Contains(why, "has no voting role") {
			t.Errorf("%s was answered %v, want a refusal", from, a.data)
		}
	}
}

// A key the leader's setup made, when the lead moved before the setup could
// publish it, is deleted: left active, this agent would hand it to the next
// leader, and publish it the next time it leads, though the parent never saw
// it.
func TestAKeyMadeForALostLeadIsNotLeftActive(t *testing.T) {
	const zone = "lostlead.example."
	hdb := NewHsyncDB(newMPTestKeyDB(t))
	if _, err := hdb.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: zone,
		Keyname: zone, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "leader-election"}); err != nil {
		t.Fatalf("the key the setup made: %v", err)
	}
	sak, err := hdb.GetSig0Keys(zone, tdns.Sig0StateActive)
	if err != nil || len(sak.Keys) != 1 {
		t.Fatalf("the active keys after the setup made one: %v, %v", sak, err)
	}
	dropKeyMadeForALostLead(hdb, zone, zone, sak.Keys[0].KeyRR.KeyTag())
	ids, err := activeSig0KeyIDs(hdb, zone)
	if err != nil {
		t.Fatalf("the active keys after the delete: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("the key made for a lead that moved is still active: %v", ids)
	}
}

// A key is deleted only when it is the zone's only active key. With two, the
// one the setup believes it made may be the other, the one the parent trusts,
// and a delete cannot be undone: both stay.
func TestAKeyIsNotDeletedWhenItIsNotTheOnlyActiveOne(t *testing.T) {
	const zone = "twokeys.example."
	hdb := NewHsyncDB(newMPTestKeyDB(t))
	for range 2 {
		if _, err := hdb.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: zone,
			Keyname: zone, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
			t.Fatalf("a key: %v", err)
		}
	}
	ids, err := activeSig0KeyIDs(hdb, zone)
	if err != nil || len(ids) != 2 {
		t.Fatalf("the active keys before: %v, %v", ids, err)
	}
	for id := range ids {
		dropKeyMadeForALostLead(hdb, zone, zone, id)
		break
	}
	after, err := activeSig0KeyIDs(hdb, zone)
	if err != nil {
		t.Fatalf("the active keys after: %v", err)
	}
	if len(after) != 2 {
		t.Errorf("a key was deleted while the zone had two active keys: %v left of %v", after, ids)
	}
}

// A new leader asks only the peers that may hold the zone's key. An auditor
// never answers, so asking it cost the full timeout, and a key from an agent
// that may not hold the zone's key is not the group's key.
func TestTheLeaderAsksOnlyPeersThatMayHoldTheKey(t *testing.T) {
	const zone = "asked.example."
	handoverZone(t, zone)
	var agents []*Agent
	for _, id := range []AgentId{"alice.agent.example.", "bob.agent.example.", "carol.agent.example.", "dave.agent.example."} {
		agents = append(agents, &Agent{Peer: hsync.NewPeer(id)})
	}
	var asked []AgentId
	for _, a := range sig0KeyPeers(zone, agents, "alice.agent.example") { // alice leads; her own identity without the dot
		asked = append(asked, a.ID)
	}
	if len(asked) != 1 || asked[0] != "bob.agent.example." {
		t.Errorf("the leader asks %v, want only bob, the other agent with a voting role", asked)
	}
}
