package tdnsmp

import (
	"slices"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// keyEditRig is the agent API of roleA, which votes in the zone, with a
// keystore, a copy of the zone and a data repo: what an operator's KEY edit
// reads (#340).
type keyEditRig struct {
	*agentAPIRig
	zd  *tdns.ZoneData
	kdb *tdns.KeyDB
}

func newKeyEditRig(t *testing.T, zone string, leader AgentId) *keyEditRig {
	t.Helper()
	r := &keyEditRig{agentAPIRig: newAgentAPIRig(t, roleA, zone), kdb: newMPTestKeyDB(t)}
	mpzd, ok := Zones.Get(zone)
	if !ok {
		t.Fatalf("zone %s not found", zone)
	}
	r.zd = mpzd.ZoneData
	r.conf.Config.Internal.KeyDB = r.kdb
	r.conf.InternalMp.LeaderElectionManager.elections[r.zone] = &LeaderElection{Zone: r.zone, Leader: leader, LeaderExpiry: time.Now().Add(time.Hour)}
	return r
}

// publishes puts these KEYs at the apex of the agent's copy of the zone.
func (r *keyEditRig) publishes(t *testing.T, keys ...*dns.KEY) {
	t.Helper()
	apex, ok := r.zd.Data.Get(r.zd.ZoneName)
	if !ok {
		t.Fatal("the zone has no apex")
	}
	var rrs []dns.RR
	for _, k := range keys {
		rrs = append(rrs, k)
	}
	apex.RRtypes.Set(dns.TypeKEY, core.RRset{RRs: rrs})
	r.zd.Data.Set(r.zd.ZoneName, apex)
	r.zd.InstallInitialSnapshot()
}

// holds puts these KEYs in the agent's own data, as an edit or its own read
// of its combiner does.
func (r *keyEditRig) holds(t *testing.T, keys ...*dns.KEY) {
	t.Helper()
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	nar, err := NewAgentRepo()
	if err != nil {
		t.Fatal(err)
	}
	var rrs []dns.RR
	for _, k := range keys {
		rrs = append(rrs, k)
	}
	nod := tdns.NewOwnerData(string(r.zone))
	nod.RRtypes.Set(dns.TypeKEY, core.RRset{Name: string(r.zone), RRtype: dns.TypeKEY, RRs: rrs})
	nar.Set(roleA, nod)
	zdr.Set(r.zone, nar)
	r.conf.InternalMp.ZoneDataRepo = zdr
}

// edit posts one edit, with the data engine answering, and returns what
// reached the engine: nil when nothing did.
func (r *keyEditRig) edit(t *testing.T, amp AgentMgmtPost) (AgentMgmtResponse, *ZoneUpdate) {
	t.Helper()
	got := make(chan *ZoneUpdate, 1)
	stop := make(chan struct{})
	go func() {
		select {
		case u := <-r.msgQs.SynchedDataUpdate:
			got <- u.Update
			u.Response <- &AgentMsgResponse{Msg: "taken"}
		case <-stop:
		}
	}()
	resp := r.post(t, amp)
	close(stop)
	select {
	case u := <-got:
		return resp, u
	default:
		return resp, nil
	}
}

func keyStrings(keys ...*dns.KEY) []string {
	out := []string{}
	for _, k := range keys {
		out = append(out, k.String())
	}
	slices.Sort(out)
	return out
}

// replacedKEYs is the set an update replaces the agent's KEYs with.
func replacedKEYs(t *testing.T, u *ZoneUpdate) []string {
	t.Helper()
	if u == nil {
		t.Fatal("nothing reached the data engine")
	}
	op, ok := opOf(u, "KEY")
	if !ok || op.Operation != "replace" {
		t.Fatalf("no replace of the KEY in %+v", u.Operations)
	}
	out := append([]string{}, op.Records...)
	slices.Sort(out)
	return out
}

// An operator adds no KEY through the agent, at the leader or at a member, by
// force or not: the zone's KEY is the group's. Nothing reaches the data
// engine. Other types are taken as before.
func TestAnOperatorsAddOfAKEYIsRefused(t *testing.T) {
	for _, c := range []struct {
		zone   string
		leader AgentId
	}{
		{"added.leader.key.example.", roleA},
		{"added.member.key.example.", roleB},
	} {
		r := newKeyEditRig(t, c.zone, c.leader)
		k := testSig0Key(t, r.kdb, c.zone)
		other := testSig0Key(t, newMPTestKeyDB(t), c.zone)
		r.publishes(t, k.key)
		for _, amp := range []AgentMgmtPost{
			{Command: "add-rr", RRs: []string{other.key.String()}},
			{Command: "add-rr", RRs: []string{k.key.String()}},
			{Command: "add-rr", RRs: []string{other.key.String()}, Data: map[string]any{"force": true}},
			{Command: "add-rr", RRs: []string{c.zone + " 3600 IN NS ns.a.role.example.", other.key.String()}},
		} {
			resp, u := r.edit(t, amp)
			if !resp.Error || resp.ErrorMsg != addedKEYRefusal(r.zone) {
				t.Errorf("%s: %v %q, want the refusal", c.zone, resp.Error, resp.ErrorMsg)
			}
			if u != nil {
				t.Errorf("%s: a refused add reached the data engine: %+v", c.zone, u.Operations)
			}
		}
		if resp, u := r.edit(t, AgentMgmtPost{Command: "add-rr", RRs: []string{c.zone + " 3600 IN NS ns.a.role.example."}}); resp.Error || u == nil {
			t.Errorf("%s: an add of an NS: %q, reached the engine: %v", c.zone, resp.ErrorMsg, u != nil)
		}
	}
}

// parentSyncByAgents adds parentsync=agent to the zone's HSYNCPARAM.
func parentSyncByAgents(t *testing.T, zd *tdns.ZoneData) {
	t.Helper()
	apex, ok := zd.Data.Get(zd.ZoneName)
	if !ok {
		t.Fatal("the zone has no apex")
	}
	rrs := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNCPARAM).RRs
	if len(rrs) != 1 {
		t.Fatalf("the zone has %d HSYNCPARAM records", len(rrs))
	}
	hp := rrs[0].(*dns.PrivateRR).Data.(*core.HSYNCPARAM)
	hp.Value = append(hp.Value, &core.HSYNCPARAMParentSync{Value: core.HsyncParentSyncAgent})
	zd.Data.Set(zd.ZoneName, apex)
	zd.InstallInitialSnapshot()
	Zones.Invalidate(zd.ZoneName)
}

// The edit policy answers first: with parentsync=owner a KEY is refused for
// that, as before. With parentsync=agent it lets the KEY pass, and the add is
// refused because the KEY is the group's.
func TestTheEditPolicyAnswersBeforeTheKEYsRefusal(t *testing.T) {
	const zone = "policy.key.example."
	r := newKeyEditRig(t, zone, roleA)
	k := testSig0Key(t, r.kdb, zone)
	r.zd.Options[tdns.OptMultiProvider] = true
	resp, u := r.edit(t, AgentMgmtPost{Command: "add-rr", RRs: []string{k.key.String()}})
	if !resp.Error || !strings.Contains(resp.ErrorMsg, "KEY submissions not allowed") {
		t.Errorf("parentsync=owner: %v %q, want the edit policy's refusal", resp.Error, resp.ErrorMsg)
	}
	if u != nil {
		t.Errorf("parentsync=owner: a refused add reached the data engine: %+v", u.Operations)
	}
	parentSyncByAgents(t, r.zd)
	resp, u = r.edit(t, AgentMgmtPost{Command: "add-rr", RRs: []string{k.key.String()}})
	if !resp.Error || resp.ErrorMsg != addedKEYRefusal(r.zone) {
		t.Errorf("parentsync=agent: %v %q, want the refusal", resp.Error, resp.ErrorMsg)
	}
	if u != nil {
		t.Errorf("parentsync=agent: a refused add reached the data engine: %+v", u.Operations)
	}
}

// A delete of a KEY replaces what the agent holds of its own, in the slot a
// combiner keeps the leader's published KEY in. At the leader the replace
// keeps the KEY it publishes. Nothing is added at a member, where the zone
// publishes none or another KEY, or while the apex carries several, where
// the operator picks (decision 98).
func TestADeleteOfAKEYKeepsTheKEYTheLeaderPublishes(t *testing.T) {
	const us = AgentId(roleA)
	const them = AgentId(roleB)
	for _, c := range []struct {
		name      string
		leader    AgentId
		publishes func(k, x *dns.KEY) []*dns.KEY
		holds     func(k, x *dns.KEY) []*dns.KEY
		deletes   func(k, x *dns.KEY) *dns.KEY
		want      func(k, x *dns.KEY) []*dns.KEY
	}{
		{name: "leader, own data without the published KEY", leader: us,
			publishes: func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{k} },
			holds:     func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{x} },
			deletes:   func(k, x *dns.KEY) *dns.KEY { return x },
			want:      func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{k} }},
		{name: "leader, own data with the published KEY", leader: us,
			publishes: func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{k} },
			holds:     func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{k, x} },
			deletes:   func(k, x *dns.KEY) *dns.KEY { return x },
			want:      func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{k} }},
		{name: "member", leader: them,
			publishes: func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{k} },
			holds:     func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{x} },
			deletes:   func(k, x *dns.KEY) *dns.KEY { return x },
			want:      func(k, x *dns.KEY) []*dns.KEY { return nil }},
		{name: "leader, the zone publishes none", leader: us,
			publishes: func(k, x *dns.KEY) []*dns.KEY { return nil },
			holds:     func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{x} },
			deletes:   func(k, x *dns.KEY) *dns.KEY { return x },
			want:      func(k, x *dns.KEY) []*dns.KEY { return nil }},
		{name: "leader, the zone publishes the KEY deleted", leader: us,
			publishes: func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{x} },
			holds:     func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{x} },
			deletes:   func(k, x *dns.KEY) *dns.KEY { return x },
			want:      func(k, x *dns.KEY) []*dns.KEY { return nil }},
		{name: "leader, several, the other KEY goes", leader: us,
			publishes: func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{k, x} },
			holds:     func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{k, x} },
			deletes:   func(k, x *dns.KEY) *dns.KEY { return x },
			want:      func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{k} }},
		{name: "leader, several, its own key goes", leader: us,
			publishes: func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{k, x} },
			holds:     func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{k, x} },
			deletes:   func(k, x *dns.KEY) *dns.KEY { return k },
			want:      func(k, x *dns.KEY) []*dns.KEY { return []*dns.KEY{x} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			const zone = "deleted.key.example."
			r := newKeyEditRig(t, zone, c.leader)
			k, x := testSig0Key(t, r.kdb, zone).key, testSig0Key(t, newMPTestKeyDB(t), zone).key
			r.publishes(t, c.publishes(k, x)...)
			r.holds(t, c.holds(k, x)...)
			resp, u := r.edit(t, AgentMgmtPost{Command: "del-rr", RRs: []string{c.deletes(k, x).String()}})
			if resp.Error {
				t.Fatalf("the delete: %q", resp.ErrorMsg)
			}
			if got, want := replacedKEYs(t, u), keyStrings(c.want(k, x)...); !slices.Equal(got, want) {
				t.Errorf("the replace: %v, want %v", got, want)
			}
		})
	}
}

// The leader's own data holds the KEY it publishes after its own read of its
// combiner. An operator's delete of it would take it away at every signing
// combiner: it is refused. A member's delete of it is taken: it holds its
// own contribution only.
func TestTheLeaderRefusesToRemoveTheKEYItPublishes(t *testing.T) {
	for _, c := range []struct {
		zone    string
		leader  AgentId
		refused bool
	}{
		{"removed.leader.key.example.", roleA, true},
		{"removed.member.key.example.", roleB, false},
	} {
		r := newKeyEditRig(t, c.zone, c.leader)
		k := testSig0Key(t, r.kdb, c.zone).key
		r.publishes(t, k)
		r.holds(t, k)
		resp, u := r.edit(t, AgentMgmtPost{Command: "del-rr", RRs: []string{k.String()}})
		if c.refused {
			if !resp.Error || resp.ErrorMsg != publishedKEYRefusal(r.zone) {
				t.Errorf("%s: %v %q, want the refusal", c.zone, resp.Error, resp.ErrorMsg)
			}
			if u != nil {
				t.Errorf("%s: a refused delete reached the data engine: %+v", c.zone, u.Operations)
			}
			continue
		}
		if resp.Error {
			t.Errorf("%s: the delete: %q", c.zone, resp.ErrorMsg)
		}
		if got := replacedKEYs(t, u); len(got) != 0 {
			t.Errorf("%s: the replace: %v, want none", c.zone, got)
		}
	}
}

// From the operator's delete to what a signing combiner serves: the leader's
// KEY, published by instruction, stays. This is the bug by delete of #340: a
// replace of the leader's KEY data with nothing took it away.
func TestADeleteAtTheLeaderLeavesThePublishedKEYServed(t *testing.T) {
	const zone = "served.key.example."
	r := newKeyEditRig(t, zone, roleA)
	k, x := testSig0Key(t, r.kdb, zone).key, testSig0Key(t, newMPTestKeyDB(t), zone).key
	r.publishes(t, k)
	r.holds(t, x)
	resp, u := r.edit(t, AgentMgmtPost{Command: "del-rr", RRs: []string{x.String()}})
	if resp.Error || u == nil {
		t.Fatalf("the delete: %q, reached the engine: %v", resp.ErrorMsg, u != nil)
	}

	// The combiner serves the same records under a zone name of its own. Under
	// the agent's name it would read that rig's roles, whose parentsync=owner
	// applies no KEY, and this test would pass without the fix.
	const atCombiner = "at." + zone
	there := func(record string) string { return strings.ReplaceAll(record, zone, atCombiner) }
	published := there(k.String())
	_, mpzd := actingCombiner(t, atCombiner, actRecords(`serial="5" servers="alpha,beta" signers="alpha,beta" parentsync="agent"`)...)
	mpzd.combinerApplyPublishInstruction(&CombinerSyncRequest{SenderID: actOther, Zone: atCombiner,
		Publish: &core.PublishInstruction{KEYRRs: []string{published}, Locations: []string{"at-apex"}}}, nil)
	if got := servedTypes(t, mpzd, dns.TypeKEY); !slices.Equal(got, []string{published}) {
		t.Fatalf("the combiner serves %v after the instruction, want the published KEY", got)
	}
	var ops []core.RROperation
	for _, op := range u.Operations {
		records := []string{}
		for _, record := range op.Records {
			records = append(records, there(record))
		}
		ops = append(ops, core.RROperation{Operation: op.Operation, RRtype: op.RRtype, Records: records})
	}
	req := &CombinerSyncRequest{SenderID: actOther, Zone: atCombiner, DistributionID: nextDistributionID(), Timestamp: time.Now(), Operations: ops}
	mpzd.combinerProcessOperations(req, atCombiner, nil, map[string]bool{actUs: true}, mpzd.getEditPolicy())
	if _, err := mpzd.CombineWithLocalChanges(); err != nil {
		t.Fatal(err)
	}
	if got := servedTypes(t, mpzd, dns.TypeKEY); !slices.Equal(got, []string{published}) {
		t.Errorf("after the delete the combiner serves %v, want the published KEY", got)
	}
}

// The KEY taken by the leader and published by instruction goes as before,
// with an operator's add of a KEY refused beside it: the leader's publication
// is no operator's edit.
func TestTheLeadersPublicationIsNoOperatorsEdit(t *testing.T) {
	r := newKeyRoundRig(t, "published.key.example.", "UPDATE")
	parentSyncByAgents(t, r.mpzd.ZoneData)
	k := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	other := testSig0Key(t, newMPTestKeyDB(t), string(r.zone))
	r.publish(t, k)
	r.caughtUp()
	resp := postAgent(t, r.conf, AgentMgmtPost{Command: "add-rr", Zone: r.zone, RRs: []string{other.key.String()}})
	if !resp.Error || resp.ErrorMsg != addedKEYRefusal(r.zone) {
		t.Errorf("an operator's add: %v %q, want the refusal", resp.Error, resp.ErrorMsg)
	}
	if !r.decide(map[AgentId]keyReply{r.them: {outcome: keyGot, data: keyData(k)}}) {
		t.Fatal("a round that brought the key did not end")
	}
	if keyid := r.polled(t, "the leader"); keyid != k.keyid {
		t.Errorf("the leader polled key %d, want %d", keyid, k.keyid)
	}
	if line := r.alog.String(); !strings.Contains(line, "KEY + PublishInstruction sent to combiner") {
		t.Errorf("the leader did not publish the KEY by instruction:\n%s", line)
	}
}
