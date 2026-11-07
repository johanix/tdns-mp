package tdnsmp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// TestAPIagentDebug_DumpZoneDataRepo is an end-to-end smoke test of the
// agent's debug request path: HTTP POST -> APIagentDebug handler ->
// MsgQs.SynchedDataCmd -> SynchedDataEngine -> response -> HTTP body.
//
// This is the path behind `tdns-mpcli agent zone edits list`. It is the
// layer that actually broke in the silent-SDE footgun (2026-05-22): the
// handler returned 200 with Error=true / "No response from
// SynchedDataCmd after 2 seconds" because nothing serviced the engine
// command channel. This test asserts a clean (Error=false) response, so
// it fails if any link in that chain stops carrying the request.
func TestAPIagentDebug_DumpZoneDataRepo(t *testing.T) {
	ctx := t.Context() // cancelled at cleanup; stops the engine goroutine

	msgQs := &MsgQs{
		SynchedDataUpdate: make(chan *SynchedDataUpdate, 4),
		SynchedDataCmd:    make(chan *SynchedDataCmd, 4),
		// APIagentDebug() os.Exit(1)s if DebugCommand is nil, so it must
		// be set even though dump-zonedatarepo doesn't use it.
		DebugCommand: make(chan *AgentMgmtPostPlus, 4),
	}
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Identity: "test-agent.example."})
	conf.InternalMp.MsgQs = msgQs

	go conf.SynchedDataEngine(ctx, msgQs)

	handler := conf.APIagentDebug()

	body, err := json.Marshal(AgentMgmtPost{Command: "dump-zonedatarepo"})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/agent/debug", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler(w, req)

	res := w.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", res.StatusCode)
	}

	var resp AgentMgmtResponse
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error {
		t.Fatalf("dump-zonedatarepo returned error: %s", resp.ErrorMsg)
	}
}

// agentAPIRig is the agent API of the agent self, in a zone with one provider
// that votes (roleA), an auditor (roleX) and a record with no role (roleN).
// Its command and update queues are kept, so that a test sees what reached
// them.
type agentAPIRig struct {
	conf  *Config
	zone  ZoneName
	msgQs *MsgQs
}

func newAgentAPIRig(t *testing.T, self, zone string) *agentAPIRig {
	t.Helper()
	seedRoles(t, zone, []string{roleA}, []string{roleX}, []string{roleN})
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: self})
	msgQs := &MsgQs{Command: make(chan *AgentMgmtPostPlus, 4), SynchedDataUpdate: make(chan *SynchedDataUpdate, 4)}
	conf.InternalMp.MsgQs = msgQs
	lem, _ := newRoleLEM(t, self, time.Minute)
	conf.InternalMp.LeaderElectionManager = lem
	conf.InternalMp.AgentRegistry = &AgentRegistry{}
	return &agentAPIRig{conf: conf, zone: ZoneName(zone), msgQs: msgQs}
}

func (r *agentAPIRig) post(t *testing.T, amp AgentMgmtPost) AgentMgmtResponse {
	t.Helper()
	amp.Zone = r.zone
	body, _ := json.Marshal(amp)
	w := httptest.NewRecorder()
	r.conf.APIagent(t.Context(), nil, nil)(w, httptest.NewRequest(http.MethodPost, "/api/v1/agent", bytes.NewReader(body)))
	var resp AgentMgmtResponse
	if err := json.NewDecoder(w.Result().Body).Decode(&resp); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	return resp
}

func (r *agentAPIRig) queued() int {
	return len(r.msgQs.Command) + len(r.msgQs.SynchedDataUpdate)
}

// An agent whose provider has no role in the zone, a record with no role or
// an auditor, refuses its operator's edits: add-rr, del-rr and
// update-local-zonedata. Nothing reaches the update queue or the command
// queue. An agent with a role takes them as before.
func TestAnAgentWithNoRoleRefusesItsOperatorsEdits(t *testing.T) {
	const zone = "norole.api.example."
	edits := []AgentMgmtPost{
		{Command: "add-rr", RRs: []string{zone + " 3600 IN NS ns.n.role.example."}},
		{Command: "del-rr", RRs: []string{zone + " 3600 IN NS ns.n.role.example."}},
		{Command: "update-local-zonedata", AddedRRs: []string{zone + " 3600 IN NS ns.n.role.example."}},
	}
	for _, self := range []string{roleN, roleX} {
		r := newAgentAPIRig(t, self, zone)
		for _, amp := range edits {
			resp := r.post(t, amp)
			if !resp.Error || resp.ErrorMsg != noRoleEditRefusal(r.zone) {
				t.Errorf("%s at %s: error=%v %q, want the refusal", amp.Command, self, resp.Error, resp.ErrorMsg)
			}
		}
		if n := r.queued(); n != 0 {
			t.Errorf("%d edits of %s reached a queue", n, self)
		}
	}

	r := newAgentAPIRig(t, roleA, zone)
	go func() {
		u := <-r.msgQs.SynchedDataUpdate
		u.Response <- &AgentMsgResponse{Msg: "taken"}
	}()
	if resp := r.post(t, edits[0]); resp.Error {
		t.Errorf("add-rr at the provider with a role: %q", resp.ErrorMsg)
	}
	go func() {
		c := <-r.msgQs.Command
		c.Response <- &AgentMgmtResponse{Msg: "taken"}
	}()
	if resp := r.post(t, edits[2]); resp.Error || resp.Msg != "taken" {
		t.Errorf("update-local-zonedata at the provider with a role: %v %q %q", resp.Error, resp.ErrorMsg, resp.Msg)
	}
}

// The local case of EvaluateUpdate refuses first, so that no path gets past:
// an edit, and the DNSKEY distribution that follows an inventory. The
// refusal is the policy's answer, not an error.
func TestALocalUpdateFromAnAgentWithNoRoleIsRefused(t *testing.T) {
	const zone = "norole.policy.example."
	seedRoles(t, zone, []string{roleA}, []string{roleX}, []string{roleN})
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	ns, _ := dns.NewRR(zone + " 3600 IN NS ns.n.role.example.")
	key := testDnskey(t, zone, 257)
	for _, tc := range []struct {
		what string
		rr   dns.RR
	}{{"an NS edit", ns}, {"a DNSKEY distribution", key}} {
		for _, self := range []string{roleN, roleX} {
			ok, msg, err := zdr.EvaluateUpdate(&SynchedDataUpdate{Zone: ZoneName(zone), AgentId: AgentId(self), UpdateType: "local",
				Update: &ZoneUpdate{Zone: ZoneName(zone), AgentId: AgentId(self), RRs: []dns.RR{tc.rr}}})
			if ok || err != nil || msg != noRoleEditRefusal(ZoneName(zone)) {
				t.Errorf("%s from %s: ok=%v err=%v msg=%q", tc.what, self, ok, err, msg)
			}
		}
	}
	if ok, msg, err := zdr.EvaluateUpdate(&SynchedDataUpdate{Zone: ZoneName(zone), AgentId: AgentId(roleA), UpdateType: "local",
		Update: &ZoneUpdate{Zone: ZoneName(zone), AgentId: AgentId(roleA), RRs: []dns.RR{key}}}); !ok || err != nil {
		t.Errorf("a DNSKEY distribution from the provider with a role: ok=%v err=%v msg=%q", ok, err, msg)
	}
}

// incomingApex is an apex as a refresh brings it: HSYNC3 records and an
// HSYNCPARAM with servers= (servedMembers' form), not yet served.
func incomingApex(t *testing.T, zone string, recs []h3rec, servers []string) *tdns.OwnerData {
	t.Helper()
	mpzd := signerTestZone(t, "incoming."+zone, newMPTestKeyDB(t))
	servedMembers(t, mpzd, recs, servers)
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("the incoming apex: %v", err)
	}
	return apex
}

// A DNSKEY distribution that is refused is not recorded as sent, by any
// caller: LocalDnskeysFromKeystate tests the role first. The inventory's
// handler records nothing and distributes nothing; once the role comes, the
// keys go out. At a refresh the copy that decides is the incoming one.
func TestARefusedDNSKEYDistributionIsNotRecordedAsSent(t *testing.T) {
	asMPAgent(t)
	yes := true
	r := newLeaderSyncRig(t, "refused.dnskey.example.")
	r.mpzd.Ready = true
	z := r.mpzd.ZoneName
	noRole := []h3rec{{usAgent, true}, {otherAgent, true}}
	ksk := invItem(t, z, 257, KeyStateActive, &yes)
	recorded := func() int {
		r.mpzd.Lock()
		defer r.mpzd.Unlock()
		if r.mpzd.MP == nil {
			return 0
		}
		return len(r.mpzd.MP.LocalDNSKEYs) + len(r.mpzd.MP.LocalKeyStates)
	}

	servedMembers(t, r.mpzd, noRole, []string{otherAgent})
	r.mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: z, Inventory: []KeyInventoryItem{ksk}, Received: time.Now()})
	if changed, ds, err := r.mpzd.LocalDnskeysFromKeystate(usAgent, nil); changed || ds != nil || !errors.Is(err, errNoRoleInZone) {
		t.Errorf("a provider with no role: changed=%v ds=%v err=%v", changed, ds != nil, err)
	}
	r.inventory(ksk) // the inventory's handler (handleKeystateInventory)
	if n := recorded(); n != 0 {
		t.Errorf("%d keys and states recorded as distributed by a provider with no role", n)
	}
	if n := len(r.sdq); n != 0 {
		t.Errorf("%d updates queued for a provider with no role", n)
	}

	// the incoming copy decides, not the served one
	withRole := incomingApex(t, z, noRole, []string{usAgent, otherAgent})
	if _, _, err := r.mpzd.LocalDnskeysFromKeystate(usAgent, withRole); err != nil {
		t.Errorf("a refresh that gives the role: %v", err)
	}
	if n := recorded(); n == 0 {
		t.Error("a refresh that gives the role recorded nothing")
	}
	servedMembers(t, r.mpzd, noRole, []string{usAgent, otherAgent})
	withoutRole := incomingApex(t, z, noRole, []string{otherAgent})
	if _, _, err := r.mpzd.LocalDnskeysFromKeystate(usAgent, withoutRole); !errors.Is(err, errNoRoleInZone) {
		t.Errorf("a refresh that takes the role: %v", err)
	}
}

// refresh-keys says that a provider with no role distributes no keys, in
// place of "Key inventory refreshed".
func TestRefreshKeysReportsTheRefusal(t *testing.T) {
	asMPAgent(t)
	yes := true
	r := newLeaderSyncRig(t, "refresh.keys.example.")
	r.mpzd.Ready = true
	r.mpzd.SyncQ = make(chan SyncRequest, 4)
	z := r.mpzd.ZoneName
	r.mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: z, Inventory: []KeyInventoryItem{invItem(t, z, 257, KeyStateActive, &yes)}, Received: time.Now()})

	servedMembers(t, r.mpzd, []h3rec{{usAgent, true}, {otherAgent, true}}, []string{otherAgent})
	msg, err := r.mpzd.distributeRefreshedKeys(r.ctx, usAgent)
	if err == nil || !strings.Contains(err.Error(), "has no role in the zone") || msg != "" {
		t.Errorf("refresh-keys at a provider with no role: %q, %v", msg, err)
	}
	if n := len(r.mpzd.SyncQ); n != 0 {
		t.Errorf("%d distributions queued", n)
	}

	servedMembers(t, r.mpzd, []h3rec{{usAgent, true}, {otherAgent, true}}, []string{usAgent, otherAgent})
	if msg, err := r.mpzd.distributeRefreshedKeys(r.ctx, usAgent); err != nil || !strings.HasPrefix(msg, "Key inventory refreshed") {
		t.Errorf("refresh-keys at a provider with a role: %q, %v", msg, err)
	}
}

// An agent whose provider has no role in the zone cannot be asked to lead
// it: the operator's parentsync-election and parentsync-bootstrap refuse.
func TestAnAgentWithNoRoleCannotBeAskedToLead(t *testing.T) {
	const zone = "norole.lead.example."
	for _, self := range []string{roleN, roleX} {
		r := newAgentAPIRig(t, self, zone)
		for _, cmd := range []string{"parentsync-election", "parentsync-bootstrap"} {
			resp := r.post(t, AgentMgmtPost{Command: cmd})
			if !resp.Error || resp.ErrorMsg != noRoleLeadRefusal(r.zone) {
				t.Errorf("%s at %s: error=%v %q, want the refusal", cmd, self, resp.Error, resp.ErrorMsg)
			}
		}
	}
	r := newAgentAPIRig(t, roleA, zone)
	if resp := r.post(t, AgentMgmtPost{Command: "parentsync-election"}); resp.Error {
		t.Errorf("parentsync-election at the provider with a role: %q", resp.ErrorMsg)
	}
}

// An agent whose provider loses its roles leads no more, at once (decision
// 34): with its per-zone lease still held, IsLeader reads false, the status
// shows no lead of its own, and nothing is asked of the parent.
func TestAnAgentWhoseRolesAreGoneLeadsNoMore(t *testing.T) {
	asMPAgent(t)
	r := newLeaderSyncRig(t, "rolesgone.lead.example.")
	r.mpzd.Ready = true
	z := ZoneName(r.mpzd.ZoneName)
	recs := []h3rec{{usAgent, true}, {otherAgent, true}}
	servedMembers(t, r.mpzd, recs, []string{usAgent, otherAgent})
	r.leader(usAgent)
	if !r.lem.IsLeader(z) {
		t.Fatal("the agent with a role does not lead")
	}
	listed := false
	for _, ls := range r.lem.GetAllLeaders() {
		listed = listed || (ls.Zone == z && ls.IsSelf)
	}
	if !listed {
		t.Fatal("the leader list does not show the lead of the agent with a role")
	}

	servedMembers(t, r.mpzd, recs, []string{otherAgent})
	if r.lem.IsLeader(z) {
		t.Error("an agent whose roles are gone still leads")
	}
	if st := r.lem.GetParentSyncStatus(z, nil, nil, nil, nil, nil); st.IsLeader || st.Leader != usAgent {
		t.Errorf("the status: leader %q, this agent's lead %v", st.Leader, st.IsLeader)
	}
	// the leader list that the peer status publishes says the same
	for _, ls := range r.lem.GetAllLeaders() {
		if ls.Zone == z && (ls.IsSelf || ls.Leader != usAgent) {
			t.Errorf("the leader list: leader %q, this agent's lead %v", ls.Leader, ls.IsSelf)
		}
	}
	if r.conf.requestDelegationSync(r.ctx, string(z), "this agent was elected the zone's delegation sync leader") {
		t.Error("a sync was asked for by an agent whose roles are gone")
	}
	if n := r.requests(t); n != 0 {
		t.Errorf("%d syncs queued", n)
	}
}

// The operator's resync on an agent whose provider has no role sends none of
// its own data, to the other agents or to its combiner, and says so. With a
// role it sends its data to both, as before.
func TestResyncPushFromAnAgentWithNoRoleSendsNoOwnDataToPeersOrItsCombiner(t *testing.T) {
	asMPAgent(t)
	const zone = "resync.norole.example."
	const combiner = "combiner.a.role.example."
	zd := seedRoles(t, zone, []string{roleA, roleB}, nil, nil)
	zd.Logger = log.New(io.Discard, "", 0)
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: roleA})
	queue := transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{})
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: conf.MpConfig()}
	conf.InternalMp.AgentRegistry = ar
	conf.InternalMp.MPTransport = &MPTransportBridge{
		TransportManager: &transport.TransportManager{ReliableQueue: queue, PeerRegistry: transport.NewPeerRegistry()},
		agentRegistry:    ar,
		combinerID:       combiner,
	}
	msgQs := &MsgQs{SynchedDataUpdate: make(chan *SynchedDataUpdate, 4), SynchedDataCmd: make(chan *SynchedDataCmd, 4)}
	conf.InternalMp.MsgQs = msgQs
	runEngine(t, conf, msgQs)

	// this provider's CDS, stored while it had its role
	cds := &dns.CDS{DS: *testDnskey(t, zone, 257).ToDS(dns.SHA256)}
	cds.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 120}
	done := make(chan *AgentMsgResponse, 1)
	msgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: zone, AgentId: roleA, UpdateType: "local",
		Update: &ZoneUpdate{Zone: zone, AgentId: roleA, RRs: []dns.RR{cds},
			Operations: []core.RROperation{{Operation: "replace", RRtype: "CDS", Records: []string{cds.String()}}}}, Response: done}
	select {
	case r := <-done:
		if r.Error {
			t.Fatalf("the local update: %s", r.ErrorMsg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the local update got no answer")
	}
	sent := func() (combinerMsgs, agentMsgs int) {
		for _, m := range queue.GetPendingMessages() {
			if m.RecipientID == combiner {
				combinerMsgs++
			} else {
				agentMsgs++
			}
		}
		return
	}
	resync := func() *SynchedDataCmdResponse {
		t.Helper()
		resp := make(chan *SynchedDataCmdResponse, 1)
		msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "resync", Zone: zone, Response: resp}
		select {
		case r := <-resp:
			return r
		case <-time.After(30 * time.Second):
			t.Fatal("the resync got no answer")
		}
		return nil
	}

	// the other provider's CDS, as it distributed it
	theirs := &dns.CDS{DS: *testDnskey(t, zone, 257).ToDS(dns.SHA256)}
	theirs.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 120}
	done = make(chan *AgentMsgResponse, 1)
	msgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: zone, AgentId: roleB, UpdateType: "remote", DeliveredBy: roleB,
		OriginatingDistID: "b-1", OriginatingTime: time.Now(),
		Update: &ZoneUpdate{Zone: zone, AgentId: roleB,
			Operations: []core.RROperation{{Operation: "replace", RRtype: "CDS", Records: []string{theirs.String()}}}}, Response: done}
	select {
	case r := <-done:
		if r.Error {
			t.Fatalf("the remote update: %s", r.ErrorMsg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the remote update got no answer")
	}

	c0, a0 := sent()
	if r := resync(); r.Error || strings.Contains(r.Msg, "none of this provider's data is sent") {
		t.Fatalf("the resync with a role: %+v", r)
	}
	c1, a1 := sent()
	if c1 == c0 || a1 == a0 {
		t.Fatalf("the resync with a role sent %d to the combiner and %d to the agents", c1-c0, a1-a0)
	}

	setRoles(t, zd, []string{roleB}, nil)
	r := resync()
	if !strings.Contains(r.Msg, noRolePushNote(zone)) {
		t.Errorf("the resync without a role says %q", r.Msg)
	}
	// the other agent's data still goes to the combiner, under its name;
	// none of this provider's goes anywhere
	c2, a2 := sent()
	if c2 != c1+1 || a2 != a1 {
		t.Errorf("the resync without a role sent %d to the combiner and %d to the agents, want the other agent's data to the combiner alone", c2-c1, a2-a1)
	}

	// The combiner's agent-resync asks the agent for its own data alone
	// (resync-targeted): with no role it sends none, and says so.
	targeted := func() *SynchedDataCmdResponse {
		t.Helper()
		resp := make(chan *SynchedDataCmdResponse, 1)
		msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "resync-targeted", Zone: zone, TargetAgent: combiner, Response: resp}
		r, ok := recvWithin(resp, 10*time.Second)
		if !ok {
			t.Fatal("resync-targeted got no answer")
		}
		return r
	}
	if r := targeted(); r.Msg != noRolePushNote(zone) {
		t.Errorf("resync-targeted without a role says %q", r.Msg)
	}
	if c3, a3 := sent(); c3 != c2 || a3 != a2 {
		t.Errorf("resync-targeted without a role sent %d to the combiner and %d to the agents", c3-c2, a3-a2)
	}
	setRoles(t, zd, []string{roleA, roleB}, nil)
	if r := targeted(); r.Error || r.Msg == noRolePushNote(zone) {
		t.Errorf("resync-targeted with a role: %+v", r)
	}
	if c4, _ := sent(); c4 != c2+1 {
		t.Errorf("resync-targeted with a role sent %d to the combiner, want this agent's data", c4-c2)
	}
}

// Only the providers in signers= other than this agent are named as silent
// about their keys: not an auditor, not a server that does not sign.
func TestOnlySigningProvidersAreNamedSilent(t *testing.T) {
	const zone = "silent.keys.example."
	zd := seedZoneWithHSYNC3(t, zone, roleA, roleB, roleN, roleX)
	apex, _ := zd.GetOwner(zd.ZoneName)
	hp, err := dns.NewRR(zone + ` 3600 IN HSYNCPARAM servers="a,b" signers="a,n" auditors="x" serial="2"`)
	if err != nil {
		t.Fatalf("HSYNCPARAM: %v", err)
	}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{hp}})
	zd.Data.Set(zd.ZoneName, *apex)
	zd.InstallInitialSnapshot()
	Zones.Invalidate(zd.ZoneName)

	tm := &MPTransportBridge{TransportManager: &transport.TransportManager{LocalID: roleA}}
	tm.logSilentAgents(ZoneName(zone))
	tm.foreignKeyStatesMu.Lock()
	silent := tm.foreignSilentSaid[ZoneName(zone)]
	tm.foreignKeyStatesMu.Unlock()
	if silent != roleN {
		t.Errorf("named silent: %q, want n alone", silent)
	}
}

// h3RRs is the zone's HSYNC3 records and its HSYNCPARAM with servers=, in
// presentation form, for a copy of the zone that a refresh brings
// (servedMembers' form).
func h3RRs(zone string, recs []h3rec, servers []string) []string {
	var out []string
	for _, r := range recs {
		h3 := &core.HSYNC3{Label: memberLabel(r.id), Identity: r.id, Upstream: "."}
		if r.on {
			h3.State = 1
		}
		out = append(out, (&dns.PrivateRR{Hdr: dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNC3, Class: dns.ClassINET, Ttl: 3600}, Data: h3}).String())
	}
	labels := make([]string, len(servers))
	for i, s := range servers {
		labels[i] = memberLabel(s)
	}
	hp := numbered(&core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMServers{Servers: labels}}})
	return append(out, (&dns.PrivateRR{Hdr: dns.RR_Header{Name: zone, Rrtype: core.TypeHSYNCPARAM, Class: dns.ClassINET, Ttl: 3600}, Data: hp}).String())
}

// At a refresh the DNSKEY distribution is judged against the incoming copy
// of the zone (MPPreRefresh), not the one being replaced: a refresh that
// gives this provider its role distributes its keys, and one that takes it
// distributes none.
func TestAtARefreshTheIncomingCopyDecidesTheDNSKEYDistribution(t *testing.T) {
	asMPAgent(t)
	yes := true
	recs := []h3rec{{usAgent, true}, {otherAgent, true}}
	for _, tc := range []struct {
		name             string
		served, incoming []string
		want             bool
	}{
		{"the refresh gives the role", []string{otherAgent}, []string{usAgent, otherAgent}, true},
		{"the refresh takes the role", []string{usAgent, otherAgent}, []string{otherAgent}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newLeaderSyncRig(t, "refresh.decides.example.")
			r.mpzd.Ready = true
			z := r.mpzd.ZoneName
			servedMembers(t, r.mpzd, recs, tc.served)
			r.mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: z, Inventory: []KeyInventoryItem{invItem(t, z, 257, KeyStateActive, &yes)}, Received: time.Now()})
			// the incoming copy brings a DNSKEY, so that the refresh asks
			// what this provider distributes
			incoming := refreshedZone(t, r.mpzd, append(h3RRs(z, recs, tc.incoming), testDnskey(t, z, 257).String())...)
			r.mpzd.MPPreRefresh(incoming, nil, nil, &MultiProviderConf{Role: "agent", Identity: usAgent})
			r.mpzd.Lock()
			got := len(r.mpzd.MP.LocalDNSKEYs) > 0
			r.mpzd.Unlock()
			if got != tc.want {
				t.Errorf("the provider's keys recorded as distributed: %v, want %v", got, tc.want)
			}
		})
	}
}

// A zone that joins a group whose leader record names this agent, and in
// which this agent does not vote, is not taken up here. Since step 8 the
// group is its make-up, so this agent, an auditor of the zone, does not vote
// in the group either: the record is one it took as an observer, or a stale
// one, and it does not lead the zone.
func TestAZoneThatJoinsAGroupItsLeaderDoesNotVoteInIsNotTakenUp(t *testing.T) {
	const zone = "joins.novote.example."
	seedRoles(t, zone, []string{roleB}, []string{roleA}, nil)
	lem, _ := newRoleLEM(t, roleA, time.Minute)
	pgm := NewProviderGroupManager(roleA)
	pgm.RecomputeGroups()
	pg := pgm.GetGroupForZone(zone)
	if pg == nil || pg.GroupHash != ComputeGroupHash([]string{roleB}, []string{roleA}, nil) {
		t.Fatalf("the zone's group is %+v, want the make-up of %s voting and %s auditing", pg, roleB, roleA)
	}
	group := pg.GroupHash
	lem.SetProviderGroupManager(pgm)
	lem.ApplyGossipElection(group, GroupElectionState{Leader: roleA, Term: 1, LeaderExpiry: time.Now().Add(time.Hour)})
	taken := make(chan ZoneName, 1)
	lem.SetOnZoneJoined(func(z ZoneName) error { taken <- z; return nil })
	lem.zoneJoinedGroup(zone, "", group)
	select {
	case z := <-taken:
		t.Errorf("%s was taken up by a leader that does not vote in it", z)
	case <-time.After(200 * time.Millisecond):
	}
}

// A DNSKEY distribution derived while this provider had a role, and refused
// by the data engine because the role was taken before it was applied, is
// not left recorded as sent: once the role is back, the same inventory
// distributes the keys.
func TestADNSKEYDistributionRefusedAfterItsDerivationIsNotLeftAsSent(t *testing.T) {
	asMPAgent(t)
	yes := true
	r := newLeaderSyncRig(t, "late.refused.dnskey.example.")
	r.mpzd.Ready = true
	z := r.mpzd.ZoneName
	recs := []h3rec{{usAgent, true}, {otherAgent, true}}
	ksk := invItem(t, z, 257, KeyStateActive, &yes)
	r.mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: z, Inventory: []KeyInventoryItem{ksk}, Received: time.Now()})

	servedMembers(t, r.mpzd, recs, []string{usAgent, otherAgent})
	changed, ds, err := r.mpzd.LocalDnskeysFromKeystate(usAgent, nil)
	if err != nil || !changed || ds == nil {
		t.Fatalf("the derivation with the role: changed=%v err=%v", changed, err)
	}
	// the role is taken before the engine applies the distribution
	servedMembers(t, r.mpzd, recs, []string{otherAgent})
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	ok, msg, err := zdr.EvaluateUpdate(&SynchedDataUpdate{Zone: ZoneName(z), AgentId: usAgent, UpdateType: "local",
		Update: &ZoneUpdate{Zone: ZoneName(z), AgentId: usAgent, Operations: []core.RROperation{{Operation: "replace", RRtype: "DNSKEY", Records: []string{ksk.KeyRR}}}}})
	if ok || err != nil || !strings.Contains(msg, "no role") {
		t.Fatalf("the distribution after the role was taken: ok=%v msg=%q err=%v", ok, msg, err)
	}
	// the role is back: the same inventory distributes the keys
	servedMembers(t, r.mpzd, recs, []string{usAgent, otherAgent})
	if changed, ds, err := r.mpzd.LocalDnskeysFromKeystate(usAgent, nil); err != nil || !changed || ds == nil || len(ds.CurrentLocalKeys) != 1 {
		t.Errorf("the derivation once the role is back: changed=%v err=%v ds=%+v", changed, err, ds)
	}
}

// With no transport, a bridge knows no identity of its agent's own, and does
// not name the agent itself as a signing provider that has not spoken.
func TestSilentProvidersAreNotNamedWithoutAnIdentity(t *testing.T) {
	asMPAgent(t)
	r := newLeaderSyncRig(t, "silent.noid.example.")
	r.mpzd.Ready = true
	z := r.mpzd.ZoneName
	servedMembers(t, r.mpzd, []h3rec{{usAgent, true}, {otherAgent, true}}, []string{usAgent, otherAgent})
	apex, _ := r.mpzd.OwnerForAnalysis(z)
	hp := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNCPARAM).RRs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM)
	hp.Value = append(hp.Value, &core.HSYNCPARAMSigners{Signers: []string{memberLabel(usAgent), memberLabel(otherAgent)}})
	r.mpzd.Data.Set(z, *apex)
	r.mpzd.InstallInitialSnapshot()
	tm := &MPTransportBridge{}
	tm.logSilentAgents(ZoneName(z))
	if said := tm.foreignSilentSaid[ZoneName(z)]; said != "" {
		t.Errorf("a bridge with no identity named %q as silent", said)
	}
}
