/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// tdns-mp #150: the agent runs tdns's DS engine. tdns's delegation sync asks
// the engine for the CDS before every NOTIFY(CDS), and with none running the
// elected leader sent none, so a parent that offers only the NOTIFY scheme
// never got a multi-provider zone's DS.

// agentStartSteps lists, in source order, what StartMPAgent starts: the name
// of every engine it hands to tdns.StartEngine or StartEngineNoError, and
// its calls to ensureDSEngineQueue and SetupAgent under those names. Read
// from the source, because the start itself needs a whole daemon to run.
func agentStartSteps(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, "start_agent.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing start_agent.go: %v", err)
	}
	var steps []string
	for _, decl := range af.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "StartMPAgent" || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				if fn.Name == "ensureDSEngineQueue" {
					steps = append(steps, fn.Name)
				}
			case *ast.SelectorExpr:
				switch fn.Sel.Name {
				case "StartEngine", "StartEngineNoError":
					if len(call.Args) >= 2 {
						if lit, ok := call.Args[1].(*ast.BasicLit); ok {
							if name, err := strconv.Unquote(lit.Value); err == nil {
								steps = append(steps, name)
							}
						}
					}
				case "SetupAgent":
					steps = append(steps, fn.Sel.Name)
				}
			}
			return true
		})
	}
	if len(steps) < 10 {
		t.Fatalf("only %d start-up steps found in StartMPAgent; the scan is broken: %v", len(steps), steps)
	}
	return steps
}

// requireAgentDSEngine fails the test unless StartMPAgent makes the DS
// engine's queue before every engine that can sign a zone, and starts the
// engine before the identity set-up, whose delegation sync asks it.
func requireAgentDSEngine(t *testing.T) {
	t.Helper()
	steps := agentStartSteps(t)
	at := func(name string) int {
		for i, s := range steps {
			if s == name {
				return i
			}
		}
		return -1
	}
	queue, engine, setup := at("ensureDSEngineQueue"), at("DSEngine"), at("SetupAgent")
	if queue < 0 || engine < 0 {
		t.Fatalf("StartMPAgent starts no DS engine (queue made: %v, engine started: %v): %v", queue >= 0, engine >= 0, steps)
	}
	for _, signs := range []string{"RefreshEngine", "KeyStateWorker", "ResignerEngine", "SetupAgent"} {
		if i := at(signs); i < 0 || queue > i {
			t.Errorf("StartMPAgent makes the DS engine's queue after %s (or does not start it): %v", signs, steps)
		}
	}
	if setup < 0 || engine > setup {
		t.Errorf("StartMPAgent starts the DS engine after the identity set-up (or runs none): %v", steps)
	}
}

// The start-up itself: StartMPAgent makes the queue and starts the engine.
func TestTheAgentStartsTheDSEngine(t *testing.T) {
	requireAgentDSEngine(t)
}

// startAgentDSEngine runs tdns's DS engine on kdb as the agent's start does:
// the queue, then the engine. It first makes sure the agent's start does.
func startAgentDSEngine(t *testing.T, ctx context.Context, kdb *tdns.KeyDB) {
	t.Helper()
	requireAgentDSEngine(t)
	ensureDSEngineQueue(kdb)
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		_ = kdb.DSEngine(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the DS engine did not stop")
		}
	})
}

// asMPAgent runs the test as the multi-provider agent: tdns's child-mode
// rules ask the app type.
func asMPAgent(t *testing.T) {
	t.Helper()
	old := tdns.Globals.App.Type
	tdns.Globals.App.Type = AppTypeMPAgent
	t.Cleanup(func() { tdns.Globals.App.Type = old })
}

// agentCustomerZone is a customer zone as an agent holds it: a secondary's
// copy of the zone its provider's signer serves, parsed through the function
// that sorts a transfer's records into the zone, multi-provider, in sync
// with its parent through the agents, and signed by nobody here. With cds it
// carries the CDS of its KSK, as the signers serve it. The agent's owner
// answers the zone's DS intent from its signer's inventory: that KSK.
func agentCustomerZone(t *testing.T, name string, kdb *tdns.KeyDB, cds bool) (*tdns.ZoneData, *dns.DNSKEY) {
	t.Helper()
	ksk := testDnskey(t, name, 257)
	zsk := testDnskey(t, name, 256)
	zone := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n"+
		"%s 3600 IN NS ns1.%s\nns1.%s 3600 IN A 192.0.2.1\n%s\n%s\n", name, name, name, name, name, name, ksk, zsk)
	if cds {
		rr := &dns.CDS{DS: *ksk.ToDS(dns.SHA256)}
		rr.Hdr = dns.RR_Header{Name: name, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 120}
		zone += rr.String() + "\n"
	}
	zd := &tdns.ZoneData{
		ZoneName:  name,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Secondary,
		Logger:    log.New(io.Discard, "", 0),
		Options:   map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true, tdns.OptParentSync: true},
		KeyDB:     kdb,
	}
	if _, _, err := zd.ReadZoneData(zone, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	tdns.Zones.Set(name, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(name)
		Zones.Invalidate(name)
	})
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.StopPublisher)
	if !zd.Ready {
		t.Fatal("the agent's copy of the zone did not become Ready")
	}

	yes := true
	owner := NewMPKeyLifecycleOwner(func() *tdns.KeyDB { return nil })
	owner.SetInventory(name, &KeyInventorySnapshot{SenderID: "signer.us.example.", Zone: name, Owned: true, Received: time.Now(),
		Inventory: []KeyInventoryItem{{KeyTag: ksk.KeyTag(), Algorithm: ksk.Algorithm, Flags: ksk.Flags, State: KeyStateActive, KeyRR: ksk.String(), Pub: true, Sign: true, DS: &yes}}})
	tdns.RegisterKeyLifecycleOwner(owner)
	t.Cleanup(func() { tdns.RegisterKeyLifecycleOwner(nil) })
	return zd, ksk
}

// servedCdsTags is the key tags of the CDS RRset the zone serves, sorted.
func servedCdsTags(t *testing.T, zd *tdns.ZoneData) []uint16 {
	t.Helper()
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("GetOwner(apex): owner=%v err=%v", apex, err)
	}
	var tags []uint16
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeCDS).RRs {
		tags = append(tags, rr.(*dns.CDS).KeyTag)
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })
	return tags
}

// notifyOnlyParent is the target a parent's DSYNC RRset names for the NOTIFY
// scheme, as tdns's discovery hands it to the sync.
var notifyOnlyParent = &tdns.DsyncTarget{
	Name: "notifications.parent.example.", Scheme: core.SchemeNotify, Port: 5354, Addresses: []string{"192.0.2.53:5354"},
}

// The leader's delegation sync of a multi-provider zone over the NOTIFY
// scheme, from the function tdns's sync plan calls for a NOTIFY candidate
// (the plan itself needs a resolver to discover the parent's DSYNC records):
// a DS difference, the DS set the owner states against a parent that holds
// none. As the agent used to start, with no DS engine, the sync is refused
// and nothing reaches the notifier. With the engine the agent starts now, a
// NOTIFY(CDS) for the zone is handed to the notifier, addressed to the
// parent's target; the engine has published nothing, asked or unasked, and
// the CDS the copy carries is as the signer served it.
func TestTheLeadersNotifyCDSNeedsTheAgentsDSEngine(t *testing.T) {
	asMPAgent(t)
	const zone = "notify.customer.example."
	kdb := newMPTestKeyDB(t) // as tdns-mp's roles get theirs: no DS engine queue
	updates := make(chan tdns.UpdateRequest, 8)
	kdb.UpdateQ = updates
	zd, ksk := agentCustomerZone(t, zone, kdb, true)
	in, err := tdns.DSIntentForZone(kdb, zone, dns.SHA256)
	if err != nil || !in.Known || len(in.Set) != 1 {
		t.Fatalf("the agent's DS intent: known=%v set=%v err=%v, want the signer's one KSK", in.Known, in.Set, err)
	}
	difference := tdns.DelegationSyncStatus{ZoneName: zone, DSAdds: in.Set}
	notifyq := make(chan tdns.NotifyRequest, 4)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// no DS engine: tdns-mp #150
	if kdb.DSEngineQ != nil {
		t.Fatal("tdns's KeyDB constructor makes the DS engine's queue itself now; the first half of this test has nothing to show")
	}
	_, _, err = zd.SyncZoneDelegationViaNotify(ctx, kdb, notifyq, difference, notifyOnlyParent)
	if err == nil || !strings.Contains(err.Error(), "no CDS for a NOTIFY(CDS) to point at") || !strings.Contains(err.Error(), "the DS engine is not running") {
		t.Fatalf("without a DS engine the sync said %v, want the refusal for want of an engine", err)
	}
	if len(notifyq) != 0 {
		t.Fatalf("without a DS engine a NOTIFY reached the notifier: %+v", <-notifyq)
	}

	startAgentDSEngine(t, ctx, kdb)
	msg, rcode, err := zd.SyncZoneDelegationViaNotify(ctx, kdb, notifyq, difference, notifyOnlyParent)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("with the DS engine the sync said %q, rcode %s, err %v", msg, dns.RcodeToString[int(rcode)], err)
	}
	select {
	case req := <-notifyq:
		if req.ZoneName != zone || req.RRtype != dns.TypeCDS || len(req.Targets) != 1 || req.Targets[0] != notifyOnlyParent.Addresses[0] {
			t.Errorf("the notifier got %s NOTIFY(%s) to %v, want NOTIFY(CDS) for %s to %v",
				req.ZoneName, dns.TypeToString[req.RRtype], req.Targets, zone, notifyOnlyParent.Addresses)
		}
	default:
		t.Fatal("with the DS engine no NOTIFY(CDS) reached the notifier")
	}
	if len(notifyq) != 0 {
		t.Errorf("a second NOTIFY reached the notifier for a DS difference alone: %+v", <-notifyq)
	}

	// unasked: a hint that the zone's keys changed is all that can reach the
	// engine for a zone it does not follow, and it leaves the zone alone
	kdb.KeysChanged(zd)
	select {
	case req := <-updates:
		t.Errorf("the agent's DS engine asked the zone updater for %v on %s", req.Actions, req.ZoneName)
	case <-time.After(300 * time.Millisecond):
	}
	if got := servedCdsTags(t, zd); len(got) != 1 || got[0] != ksk.KeyTag() {
		t.Errorf("the copy's CDS is %v after the sync, want the signer's %d untouched", got, ksk.KeyTag())
	}
}

// Before the agent's copy has the signers' CDS (the transfer that brings a
// zone's first CDS has not arrived), the engine has nothing to answer with:
// the sync fails, which the leader asks again, and no NOTIFY(CDS) points the
// parent at a zone that would show it none.
func TestTheLeadersNotifyCDSWaitsForTheSignersCDS(t *testing.T) {
	asMPAgent(t)
	const zone = "nocds.customer.example."
	kdb := newMPTestKeyDB(t)
	updates := make(chan tdns.UpdateRequest, 8)
	kdb.UpdateQ = updates
	zd, _ := agentCustomerZone(t, zone, kdb, false)
	in, err := tdns.DSIntentForZone(kdb, zone, dns.SHA256)
	if err != nil || !in.Known || len(in.Set) != 1 {
		t.Fatalf("the agent's DS intent: known=%v set=%v err=%v", in.Known, in.Set, err)
	}
	notifyq := make(chan tdns.NotifyRequest, 4)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startAgentDSEngine(t, ctx, kdb)

	_, _, err = zd.SyncZoneDelegationViaNotify(ctx, kdb, notifyq, tdns.DelegationSyncStatus{ZoneName: zone, DSAdds: in.Set}, notifyOnlyParent)
	if err == nil || !strings.Contains(err.Error(), "serves no CDS") {
		t.Fatalf("a copy with no CDS: the sync said %v, want it refused because the zone serves no CDS", err)
	}
	if len(notifyq) != 0 {
		t.Errorf("a NOTIFY reached the notifier for a zone that serves no CDS: %+v", <-notifyq)
	}
	if len(updates) != 0 {
		t.Errorf("the agent's DS engine asked the zone updater for %v", (<-updates).Actions)
	}
	if got := servedCdsTags(t, zd); len(got) != 0 {
		t.Errorf("the agent's copy serves CDS %v; the agent publishes none", got)
	}
}

// The one zone the agent's DS engine writes a CDS for is the agent's own
// identity zone, and there it is the only writer. The set-up used to write
// one too, for every SEP key of the served DNSKEY RRset; the engine writes
// the keys whose DS belongs at the parent. With a second KSK that is
// published and not yet standby (served, no DS) the two rules differ, and
// the zone would serve one set and then the other at every start.
func TestTheIdentityZonesCDSIsTheDSEnginesAlone(t *testing.T) {
	asMPAgent(t)
	kdb := newMPTestKeyDB(t)
	conf, _ := identityTestConfig(t, kdb)
	ctx := startIdentityUpdater(t, kdb)
	startAgentDSEngine(t, ctx, kdb)
	conf.Config.ParentSync.Schemes = []string{"notify"}
	// never published: the delegation sync the set-up starts waits for the
	// resolver, and what it would send is not this test's
	conf.Config.Internal.ImrReady = tdns.NewImrReadiness()

	if err := conf.SetupAgent(ctx, nil); err != nil {
		t.Fatalf("SetupAgent: %v", err)
	}
	zd, ok := tdns.Zones.Get(identityTestZone)
	if !ok || !zd.Options[tdns.OptParentSync] {
		t.Fatal("the identity zone is not a parentsync child")
	}
	var active uint16
	if rrset, err := zd.GetRRset(identityTestZone, dns.TypeDNSKEY); err == nil && rrset != nil {
		for _, rr := range rrset.RRs {
			if k, ok := rr.(*dns.DNSKEY); ok && k.Flags&dns.SEP != 0 {
				active = k.KeyTag()
			}
		}
	}
	if active == 0 {
		t.Fatal("the identity zone serves no KSK")
	}

	// the second KSK, and the DNSKEY RRset served with it
	next := mpGenKey(t, kdb, identityTestZone, tdns.DnskeyStatePublished, "KSK")
	if _, err := zd.SignZone(ctx, kdb, true); err != nil {
		t.Fatalf("SignZone: %v", err)
	}
	waitFor(t, "the published KSK in the served DNSKEY RRset", func() bool { return servedDnskeyTagsOf(t, zd)[next] })

	// the set-up's last step, as the next start takes it with these keys
	conf.startIdentityParentSync(ctx, zd)
	for _, tag := range servedCdsTags(t, zd) {
		if tag == next {
			t.Fatalf("the identity set-up published a CDS for KSK %d, which is published and has no DS: the zone serves %v", next, servedCdsTags(t, zd))
		}
	}

	// the engine's turn, as at the key state worker's next tick
	kdb.KeysChanged(zd)
	waitFor(t, "the CDS of the active KSK alone", func() bool {
		got := servedCdsTags(t, zd)
		return len(got) == 1 && got[0] == active
	})

	// and over the NOTIFY scheme: the engine has the CDS to point at
	in, err := tdns.DSIntentForZone(kdb, identityTestZone, dns.SHA256)
	if err != nil || !in.Known || len(in.Set) != 1 {
		t.Fatalf("the identity zone's DS intent: known=%v set=%v err=%v, want the active KSK", in.Known, in.Set, err)
	}
	notifyq := make(chan tdns.NotifyRequest, 4)
	if _, _, err := zd.SyncZoneDelegationViaNotify(ctx, kdb, notifyq, tdns.DelegationSyncStatus{ZoneName: identityTestZone, DSAdds: in.Set}, notifyOnlyParent); err != nil {
		t.Fatalf("the identity zone's sync over the NOTIFY scheme: %v", err)
	}
	select {
	case req := <-notifyq:
		if req.ZoneName != identityTestZone || req.RRtype != dns.TypeCDS {
			t.Errorf("the notifier got %s NOTIFY(%s), want NOTIFY(CDS) for the identity zone", req.ZoneName, dns.TypeToString[req.RRtype])
		}
	default:
		t.Fatal("no NOTIFY(CDS) for the identity zone reached the notifier")
	}
	if got := servedCdsTags(t, zd); len(got) != 1 || got[0] != active {
		t.Errorf("the identity zone serves CDS %v after the sync, want the active KSK %d alone", got, active)
	}
}

// waitFor polls cond until it holds, for at most ten seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
