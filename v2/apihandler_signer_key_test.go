package tdnsmp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// T3.5, the API: the replacement commands on an owned zone, and their
// refusal on a zone tdns-mp does not run.
func TestAPIsignerKey(t *testing.T) {
	kdb := newMPTestKeyDB(t)
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.KeyDB = kdb
	conf.SetMpConfig(&MultiProviderConf{Identity: "signer.example."})
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return kdb })
	e := NewKeyLifecycleEngine(conf, owner)
	conf.InternalMp.KeyLifecycleOwner, conf.InternalMp.KeyLifecycle = owner, e
	mpzd := signerTestZone(t, "apikey.owned.example.", kdb)
	owner.Take(mpzd.ZoneName)
	signerTestZone(t, "apikey.plain.example.", kdb)
	handler := conf.APIsignerKey()
	post := func(req SignerKeyPost) SignerKeyResponse {
		t.Helper()
		body, _ := json.Marshal(req)
		r := httptest.NewRequest(http.MethodPost, "/signer/key", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d", req.Command, w.Code)
		}
		var resp SignerKeyResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("%s: decode: %v", req.Command, err)
		}
		return resp
	}
	refused := func(req SignerKeyPost, want string) {
		t.Helper()
		if resp := post(req); !resp.Error || !strings.Contains(resp.ErrorMsg, want) {
			t.Errorf("%s on %s: error=%v %q, want a refusal naming %q", req.Command, req.Zone, resp.Error, resp.ErrorMsg, want)
		}
	}

	if resp := post(SignerKeyPost{Command: "zones"}); resp.Error || len(resp.Zones) != 1 || resp.Zones[0] != mpzd.ZoneName {
		t.Errorf("zones: %+v", resp)
	}
	refused(SignerKeyPost{Command: "status", Zone: "apikey.plain.example."}, "not run by tdns-mp")
	refused(SignerKeyPost{Command: "rollover", Zone: "apikey.plain.example.", Role: "KSK"}, "not run by tdns-mp")
	refused(SignerKeyPost{Command: "nonesuch", Zone: mpzd.ZoneName}, "unknown signer key command")

	// a key minted but not yet on its way: listed with its columns
	l := e.driver(mpzd.ZoneName)
	if l == nil {
		t.Fatal("no driver for the owned zone")
	}
	ksk, err := l.Mint("KSK")
	if err != nil {
		t.Fatal(err)
	}
	resp := post(SignerKeyPost{Command: "status", Zone: mpzd.ZoneName})
	if resp.Error || resp.Status == nil {
		t.Fatalf("status: %+v", resp)
	}
	st := resp.Status
	if len(st.Keys) != 1 || st.Keys[0].KeyId != ksk || st.Keys[0].Role != "KSK" || st.Keys[0].State != KeyStateCreated || st.Keys[0].Pub || st.Keys[0].Sign || st.Keys[0].DS == nil || *st.Keys[0].DS {
		t.Errorf("status keys: %+v, want the created KSK %d with pub=0 sign=0 ds=0", st.Keys, ksk)
	}
	if st.Policy.KSKAlgorithm == 0 || st.Policy.PropagationDelay == 0 {
		t.Errorf("status policy: %+v", st.Policy)
	}

	// retry and withdraw need a key in the right state
	refused(SignerKeyPost{Command: "retry", Zone: mpzd.ZoneName, KeyId: ksk}, "no distribution in flight")
	refused(SignerKeyPost{Command: "withdraw", Zone: mpzd.ZoneName, KeyId: ksk}, "is created")
	refused(SignerKeyPost{Command: "withdraw", Zone: mpzd.ZoneName, KeyId: 1}, "not one of the zone's own keys")

	// a rollover request shows in the status until cancelled
	if resp := post(SignerKeyPost{Command: "rollover", Zone: mpzd.ZoneName, Role: "zsk"}); resp.Error || !strings.Contains(resp.Msg, "ZSK rollover requested") {
		t.Errorf("rollover: %+v", resp)
	}
	refused(SignerKeyPost{Command: "rollover", Zone: mpzd.ZoneName, Role: "csk"}, "KSK or ZSK")
	if st := post(SignerKeyPost{Command: "status", Zone: mpzd.ZoneName}).Status; st == nil || len(st.Rollovers) != 1 || st.Rollovers[0] != "ZSK" {
		t.Errorf("status after the request: rollovers %v, want [ZSK]", st.Rollovers)
	}
	if resp := post(SignerKeyPost{Command: "rollover-cancel", Zone: mpzd.ZoneName, Role: "ZSK"}); resp.Error {
		t.Errorf("rollover-cancel: %+v", resp)
	}
	if st := post(SignerKeyPost{Command: "status", Zone: mpzd.ZoneName}).Status; st == nil || len(st.Rollovers) != 0 {
		t.Errorf("status after the cancel: rollovers %v, want none", st.Rollovers)
	}

	// policy-set: the binding is tdns's (SetZonePolicyForOwner); here a
	// stand-in that changes the bound policy, and the driver's policy
	// follows on the same call
	refused(SignerKeyPost{Command: "policy-set", Zone: mpzd.ZoneName, Policy: "longer"}, "SetZonePolicyForOwner")
	saved := bindPolicyForOwner
	t.Cleanup(func() { bindPolicyForOwner = saved })
	var bound string
	bindPolicyForOwner = func(ctx context.Context, zd *tdns.ZoneData, kdb *tdns.KeyDB, name string) (string, error) {
		bound = zd.ZoneName + "=" + name
		zd.DnssecPolicyName = name
		zd.DnssecPolicy.KSK.Lifetime = 90 * 86400
		return "bound " + name, nil
	}
	if resp := post(SignerKeyPost{Command: "policy-set", Zone: mpzd.ZoneName, Policy: "longer"}); resp.Error || resp.Msg != "bound longer" {
		t.Errorf("policy-set: %+v", resp)
	}
	if bound != mpzd.ZoneName+"=longer" {
		t.Errorf("the binding was asked for %q", bound)
	}
	if st := post(SignerKeyPost{Command: "policy", Zone: mpzd.ZoneName}).Status; st == nil || st.PolicyName != "longer" || st.Policy.KSKLifetime.Hours() != 90*24 {
		t.Errorf("after policy-set: name %q KSK lifetime %v, want longer and 2160h", st.PolicyName, st.Policy.KSKLifetime)
	}
}
