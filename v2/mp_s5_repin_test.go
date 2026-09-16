package tdnsmp

import (
	"encoding/json"
	"testing"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// T5.1: the keystate app message carries the inventory's columns and the
// owned flag in tdns core's wire form.
func TestKeystateAppMessageCarriesTheColumns(t *testing.T) {
	yes := true
	req := &PeerKeystateRequest{SenderID: "signer.example.", Zone: "z.example.", Signal: "inventory", Owned: true,
		KeyInventory: []KeyInventoryEntry{{KeyTag: 4711, Algorithm: 15, Flags: 257, State: "standby", KeyRR: "z.example. 3600 IN DNSKEY 257 3 15 dGVzdA==", Pub: true, DS: &yes}}}
	msg, err := keystateAppMessage(req, "agent.example.")
	if err != nil {
		t.Fatal(err)
	}
	var post core.AgentKeystatePost
	if err := json.Unmarshal(msg.Payload, &post); err != nil {
		t.Fatal(err)
	}
	if !post.Owned || len(post.KeyInventory) != 1 || !post.KeyInventory[0].Pub || post.KeyInventory[0].Sign || post.KeyInventory[0].DS == nil || !*post.KeyInventory[0].DS {
		t.Errorf("the wire form lost the columns or the flag: %+v", post)
	}
}

// T5.7: tdns-mp's agent app type is a multi-provider agent to tdns's
// zone-sync setup. tdns's parentsync schemes are not configured in a
// test, and their refusal is the multi-provider branch's own: reaching it
// is what the registration buys, where an app type tdns does not know is
// skipped without a word.
func TestMPAgentGetsDelegationSyncSetup(t *testing.T) {
	oldApp := tdns.Globals.App.Type
	t.Cleanup(func() { tdns.Globals.App.Type = oldApp })
	kdb := newMPTestKeyDB(t)
	mpzd := signerTestZone(t, "setup.mpagent.example.", kdb)
	mpzd.ZoneData.Options[tdns.OptParentSync] = true
	q := make(chan tdns.DelegationSyncRequest, 4)
	tdns.Globals.App.Type = AppTypeMPAgent
	if err := mpzd.ZoneData.SetupZoneSync(q); err == nil || !containsStr(err.Error(), "parentsync.schemes") {
		t.Errorf("the mp agent: err=%v, want the multi-provider branch's schemes refusal", err)
	}
	tdns.Globals.App.Type = tdns.AppType(251) // an app type tdns does not know
	if err := mpzd.ZoneData.SetupZoneSync(q); err != nil {
		t.Errorf("an unregistered app type: err=%v, want the zone skipped", err)
	}
	_ = dns.Fqdn
}
