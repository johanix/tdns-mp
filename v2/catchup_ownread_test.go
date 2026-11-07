/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"io"
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const ownCombiner = "combiner.a.role.example."

// The combiner answers RFI EDITS for a zone whose stored contributions it
// has not read with its word that they are not loaded, and no records, with
// the request's nonce; once it has read them, with its word that they are,
// and the contributions. The word travels to the request that asked.
func TestACombinerThatHasNotLoadedSaysSo(t *testing.T) {
	const zone = "notloaded.combiner.example."
	seedZoneWithHSYNC3(t, zone, roleA)
	zd, ok := Zones.Get(zone)
	if !ok {
		t.Fatal("no zone")
	}
	zd.EnsureMP()
	zd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{}
	ns, _ := dns.NewRR(zone + " 3600 IN NS ns.a.role.example.")
	zd.MP.AgentContributions[roleA] = map[string]map[uint16]core.RRset{zone: {dns.TypeNS: {RRs: []dns.RR{ns}}}}

	req := editsAnswerFor(zd, ownCombiner, zone, "n1")
	if req.Message != editsNotLoaded || len(req.AgentRecords) != 0 || req.Nonce != "n1" {
		t.Errorf("before the read: %q, %d agents, nonce %q", req.Message, len(req.AgentRecords), req.Nonce)
	}
	zd.Lock()
	zd.MP.ContributionsRead = true
	zd.Unlock()
	req = editsAnswerFor(zd, ownCombiner, zone, "n2")
	if req.Message != editsLoaded || len(req.AgentRecords[roleA][zone]) != 1 || req.Nonce != "n2" {
		t.Errorf("after the read: %q, %v, nonce %q", req.Message, req.AgentRecords, req.Nonce)
	}

	// on the wire, to the request that asked
	msg, err := editsAppMessage(&PeerEditsRequest{SenderID: ownCombiner, Zone: zone, Message: editsNotLoaded, Nonce: "n3"}, roleA)
	if err != nil {
		t.Fatal(err)
	}
	tm := &MPTransportBridge{msgQs: &MsgQs{}}
	answer, cancel := tm.msgQs.editsWaiters.register(rfiWaitKey(ownCombiner, zone, "", "n3"))
	defer cancel()
	tm.routeEditsMessage(&transport.IncomingMessage{TypeToken: "edits", SenderID: ownCombiner, TransportSender: ownCombiner, Zone: zone, Payload: msg.Payload})
	got, ok := recvWithin(answer, time.Second)
	if !ok || got.Message != editsNotLoaded {
		t.Errorf("the request got %v (answered %v), want the word that the contributions are not loaded", got, ok)
	}
}

// A combiner whose read of its stored contributions failed answers that
// they are not loaded; one whose read succeeded with nothing stored answers
// that they are, with none.
func TestACombinerWhoseReadFailedSaysNotLoaded(t *testing.T) {
	const failed, empty = "failed.combiner.example.", "empty.combiner.example."
	seedZoneWithHSYNC3(t, failed, roleA)
	seedZoneWithHSYNC3(t, empty, roleA)
	zf, _ := Zones.Get(failed)
	ze, _ := Zones.Get(empty)
	zf.restoreContributions(nil, nil, false)
	ze.restoreContributions(nil, nil, true)
	if req := editsAnswerFor(zf, ownCombiner, failed, "n"); req.Message != editsNotLoaded {
		t.Errorf("after a failed read: %q", req.Message)
	}
	if req := editsAnswerFor(ze, ownCombiner, empty, "n"); req.Message != editsLoaded || len(req.AgentRecords) != 0 {
		t.Errorf("after a read with nothing stored: %q, %v", req.Message, req.AgentRecords)
	}
}

// ownRig is an agent's data repo for a zone, and the zone, as the own read
// applies the combiner's answers to them.
type ownRig struct {
	mpzd *MPZoneData
	zdr  *ZoneDataRepo
	zone ZoneName
}

func newOwnRig(t *testing.T, zone string) *ownRig {
	t.Helper()
	zd := seedRoles(t, zone, []string{roleA, roleB}, nil, nil)
	zd.Logger = log.New(io.Discard, "", 0)
	mpzd, _ := Zones.Get(zone)
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	return &ownRig{mpzd: mpzd, zdr: zdr, zone: ZoneName(zone)}
}

func (r *ownRig) apply(word string, sentAt time.Time, recs map[string]map[string][]string) {
	r.applyAs(false, word, sentAt, recs)
}

// reread is apply for the answer to a re-read (ownReader).
func (r *ownRig) reread(word string, sentAt time.Time, recs map[string]map[string][]string) {
	r.applyAs(true, word, sentAt, recs)
}

func (r *ownRig) applyAs(reread bool, word string, sentAt time.Time, recs map[string]map[string][]string) {
	applyOwnRead(r.mpzd, &ownReadAnswer{zone: r.zone, asked: true, sentAt: sentAt, reread: reread,
		resp: &EditsResponseMsg{SenderID: ownCombiner, Zone: string(r.zone), AgentRecords: recs, Message: word}}, r.zdr, roleA)
}

func (r *ownRig) holds(agent AgentId, rrtype uint16) []string {
	repo, ok := r.zdr.Get(r.zone)
	if !ok {
		return nil
	}
	nod, ok := repo.Get(agent)
	if !ok {
		return nil
	}
	rrset, ok := nod.RRtypes.Get(rrtype)
	if !ok {
		return nil
	}
	var out []string
	for _, rr := range rrset.RRs {
		out = append(out, rr.String())
	}
	return out
}

func (r *ownRig) records(agent string, rrs ...string) map[string]map[string][]string {
	return map[string]map[string][]string{agent: {string(r.zone): rrs}}
}

// An answer that says the contributions are not loaded is neither applied
// nor the agent's own read.
func TestAnAnswerThatSaysNotLoadedIsNotTheOwnRead(t *testing.T) {
	r := newOwnRig(t, "notloaded.own.example.")
	ns := string(r.zone) + " 3600 IN NS ns.a.role.example."
	r.apply(editsNotLoaded, time.Now(), r.records(roleA, ns))
	if r.zdr.OwnStateRead(r.zone) {
		t.Error("an answer that says the contributions are not loaded counted as the own read")
	}
	if got := r.holds(roleA, dns.TypeNS); len(got) != 0 {
		t.Errorf("an answer that says the contributions are not loaded was applied: %v", got)
	}
	r.apply(editsLoaded, time.Now(), r.records(roleA, ns))
	if !r.zdr.OwnStateRead(r.zone) || len(r.holds(roleA, dns.TypeNS)) != 1 {
		t.Errorf("the loaded answer: read %v, NS %v", r.zdr.OwnStateRead(r.zone), r.holds(roleA, dns.TypeNS))
	}
}

// An answer without the loaded token, from a combiner older than its agent,
// is applied as such answers always were, and is not the agent's own read;
// the reason says what an operator can do.
func TestAnEditsAnswerWithoutTheLoadedTokenIsNotTheOwnRead(t *testing.T) {
	r := newOwnRig(t, "oldcombiner.own.example.")
	ns := string(r.zone) + " 3600 IN NS ns.a.role.example."
	r.apply("current contributions", time.Now(), r.records(roleA, ns))
	if r.zdr.OwnStateRead(r.zone) {
		t.Error("an answer without the loaded token counted as the own read")
	}
	if got := r.holds(roleA, dns.TypeNS); len(got) != 1 {
		t.Errorf("an answer without the token was not applied: %v", got)
	}
	if why := r.zdr.ownStateWhy(r.zone); !strings.Contains(why, "older than the agent") {
		t.Errorf("the reason: %q", why)
	}
}

// An older combiner's answer is applied once for the zone, and only when it
// carries records. Its empty answer, after a failed read of its store,
// clears nothing: not at a resync, and not at the re-reads that follow
// every ownReadInterval. Nor does a re-read apply records the first read
// did not have.
func TestAnOlderCombinersAnswerIsNotAppliedAgainOnEveryReRead(t *testing.T) {
	r := newOwnRig(t, "oldempty.own.example.")
	ns := string(r.zone) + " 3600 IN NS ns.a.role.example."
	r.apply("current contributions", time.Now(), r.records(roleA, ns))
	if got := r.holds(roleA, dns.TypeNS); len(got) != 1 {
		t.Fatalf("the start-up read's answer was not applied: %v", got)
	}
	r.apply("current contributions", time.Now(), nil) // a resync, empty
	for i := 0; i < 2; i++ {
		r.reread("current contributions", time.Now(), nil)
	}
	if got := r.holds(roleA, dns.TypeNS); len(got) != 1 {
		t.Errorf("an older combiner's empty answer cleared the record: %v", got)
	}
	ns2 := string(r.zone) + " 3600 IN NS ns2.a.role.example."
	r.reread("current contributions", time.Now(), r.records(roleA, ns2))
	if got := r.holds(roleA, dns.TypeNS); len(got) != 1 || !strings.Contains(got[0], "ns.a.role") {
		t.Errorf("a re-read applied an older combiner's answer: %v", got)
	}
	if r.zdr.OwnStateRead(r.zone) {
		t.Error("an older combiner's answer counted as the own read")
	}
}

// A late answer does not undo what the engine did while the request was
// out: a set whose change the combiner confirmed after the request was
// sent, and a set a replace emptied after it, are left alone. A set
// confirmed before the request, and one with no note, are applied.
func TestALateAnswerDoesNotUndoAConfirmation(t *testing.T) {
	r := newOwnRig(t, "lateconfirm.own.example.")
	ns := string(r.zone) + " 3600 IN NS ns.a.role.example."
	sentAt := time.Now()
	// the change was stored before the request and confirmed while it was out
	nsrr, _ := dns.NewRR(ns)
	r.zdr.AddConfirmedRR(r.zone, roleA, nsrr)
	r.zdr.noteCombinerSend(r.zone, roleA, []uint16{dns.TypeNS}, sentAt.Add(-time.Second), "d1")
	r.zdr.noteCombinerConfirmed(r.zone, "d1", sentAt.Add(time.Second))
	r.apply(editsLoaded, sentAt, nil) // the combiner's snapshot predates the change
	if got := r.holds(roleA, dns.TypeNS); len(got) != 1 {
		t.Errorf("a late answer undid a confirmed change: NS %v", got)
	}
}

func TestALateAnswerDoesNotBringBackWhatAReplaceRemoved(t *testing.T) {
	r := newOwnRig(t, "lateremove.own.example.")
	ns := string(r.zone) + " 3600 IN NS ns.a.role.example."
	sentAt := time.Now()
	// the replace that removed the NS was stored after the request was sent
	r.zdr.noteCombinerSend(r.zone, roleA, []uint16{dns.TypeNS}, sentAt.Add(time.Second), "d2")
	r.apply(editsLoaded, sentAt, r.records(roleA, ns))
	if got := r.holds(roleA, dns.TypeNS); len(got) != 0 {
		t.Errorf("a late answer brought back what a replace removed: NS %v", got)
	}
}

func TestAnOwnReadLeavesASetConfirmedAfterTheRequestAlone(t *testing.T) {
	r := newOwnRig(t, "confirmedafter.own.example.")
	before := string(r.zone) + " 3600 IN NS ns1.b.role.example."
	sentAt := time.Now()
	// B's set: changed before the request, confirmed before it: applied
	r.zdr.noteCombinerSend(r.zone, roleB, []uint16{dns.TypeNS}, sentAt.Add(-2*time.Second), "d3")
	r.zdr.noteCombinerConfirmed(r.zone, "d3", sentAt.Add(-time.Second))
	// A's CDS: changed before, confirmed after: left alone
	r.zdr.noteCombinerSend(r.zone, roleA, []uint16{dns.TypeCDS}, sentAt.Add(-2*time.Second), "d4")
	r.zdr.noteCombinerConfirmed(r.zone, "d4", sentAt.Add(time.Second))
	cds := &dns.CDS{DS: *testDnskey(t, string(r.zone), 257).ToDS(dns.SHA256)}
	cds.Hdr = dns.RR_Header{Name: string(r.zone), Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 120}
	recs := r.records(roleB, before)
	recs[roleA] = map[string][]string{string(r.zone): {cds.String()}}
	r.apply(editsLoaded, sentAt, recs)
	if got := r.holds(roleB, dns.TypeNS); len(got) != 1 {
		t.Errorf("a set confirmed before the request was not applied: %v", got)
	}
	if got := r.holds(roleA, dns.TypeCDS); len(got) != 0 {
		t.Errorf("a set confirmed after the request was applied: %v", got)
	}
}

// A change the combiner has not confirmed a day after it was stored never
// will be: the queue has given its message up. The combiner's answer is the
// truth for that set again.
func TestASetTheCombinerNeverConfirmedIsReadAgainAfterADay(t *testing.T) {
	r := newOwnRig(t, "unconfirmed.own.example.")
	ns := string(r.zone) + " 3600 IN NS ns1.b.role.example."
	sentAt := time.Now()
	r.zdr.noteCombinerSend(r.zone, roleB, []uint16{dns.TypeNS}, sentAt.Add(-time.Hour), "d5")
	r.apply(editsLoaded, sentAt, r.records(roleB, ns))
	if got := r.holds(roleB, dns.TypeNS); len(got) != 0 {
		t.Fatalf("a set the combiner may still confirm was applied: %v", got)
	}
	r.zdr.noteCombinerSend(r.zone, roleB, []uint16{dns.TypeNS}, sentAt.Add(-noteMaxAge-time.Minute), "d5")
	r.apply(editsLoaded, sentAt, r.records(roleB, ns))
	if got := r.holds(roleB, dns.TypeNS); len(got) != 1 {
		t.Errorf("a set the combiner never confirmed, a day on, was not applied: %v", got)
	}
}

// The own read leaves this agent's own DNSKEY set alone: the agent never
// sends it to its combiner, so no answer holds it, and an answer applied
// after the inventory would drop the keys the inventory put there. The
// start-up hydration and resync use the same apply.
func TestAnOwnReadAfterTheInventoryKeepsTheLocalDNSKEYs(t *testing.T) {
	r := newOwnRig(t, "dnskeys.own.example.")
	key := testDnskey(t, string(r.zone), 257)
	r.zdr.AddConfirmedRR(r.zone, roleA, key)
	r.apply(editsLoaded, time.Now(), nil)
	if got := r.holds(roleA, dns.TypeDNSKEY); len(got) != 1 {
		t.Errorf("the own read dropped the local DNSKEYs: %v", got)
	}
	r.apply("current contributions", time.Now(), nil) // as resync's apply of an older combiner's answer
	if got := r.holds(roleA, dns.TypeDNSKEY); len(got) != 1 {
		t.Errorf("an apply dropped the local DNSKEYs: %v", got)
	}
}

// reReadRig runs the data engine with a stand-in for the combiner's
// answers to the re-read.
type reReadRig struct {
	conf  *Config
	mpzd  *MPZoneData
	msgQs *MsgQs
	zone  ZoneName
	asks  atomic.Int32
}

func newReReadRig(t *testing.T, zone string, answer func(ctx context.Context, n int32) (*EditsResponseMsg, error)) *reReadRig {
	t.Helper()
	return newReReadRigFor(t, zone, &PeerConf{Identity: ownCombiner}, answer)
}

// newReReadRigFor is newReReadRig with the combiner the agent's
// configuration names: none when nil.
func newReReadRigFor(t *testing.T, zone string, combiner *PeerConf, answer func(ctx context.Context, n int32) (*EditsResponseMsg, error)) *reReadRig {
	t.Helper()
	asMPAgent(t)
	saved := ownReadInterval
	ownReadInterval = 20 * time.Millisecond
	t.Cleanup(func() { ownReadInterval = saved })
	zd := seedRoles(t, zone, []string{roleA, roleB}, nil, nil)
	zd.Logger = log.New(io.Discard, "", 0)
	zd.Options[tdns.OptMultiProvider] = true
	mpzd, _ := Zones.Get(zone)
	mpzd.EnsureMP()
	mpzd.MP.MPdata = &MPdata{WeAreProvider: true, OurLabel: "a"}
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: roleA, Combiner: combiner})
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: conf.MpConfig()}
	conf.InternalMp.AgentRegistry = ar
	conf.InternalMp.MPTransport = &MPTransportBridge{
		TransportManager: &transport.TransportManager{ReliableQueue: transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{}), PeerRegistry: transport.NewPeerRegistry()},
		agentRegistry:    ar, combinerID: ownCombiner,
	}
	r := &reReadRig{conf: conf, mpzd: mpzd, zone: ZoneName(zone)}
	conf.InternalMp.editsRequest = func(ctx context.Context, zd *tdns.ZoneData, _ *MPTransportBridge, _ *MsgQs) (*EditsResponseMsg, time.Time, error) {
		if zd.ZoneName != zone {
			return nil, time.Now(), context.Canceled
		}
		sentAt := time.Now()
		resp, err := answer(ctx, r.asks.Add(1))
		return resp, sentAt, err
	}
	r.msgQs = &MsgQs{SynchedDataUpdate: make(chan *SynchedDataUpdate, 4), SynchedDataCmd: make(chan *SynchedDataCmd, 16)}
	conf.InternalMp.MsgQs = r.msgQs
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); conf.SynchedDataEngine(ctx, r.msgQs) }()
	t.Cleanup(func() {
		cancel()
		<-done
		conf.InternalMp.ownReads.Wait()
	})
	return r
}

func (r *reReadRig) waitRead(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !r.ownRead(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the own read was not done after %d requests", r.asks.Load())
		}
	}
}

// ownRead asks the engine, on its own loop, whether the own read is done.
func (r *reReadRig) ownRead() bool {
	resp := make(chan *SynchedDataCmdResponse, 1)
	r.msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "dump-zonedatarepo", Zone: r.zone, Response: resp}
	if _, ok := recvWithin(resp, 5*time.Second); !ok {
		return false
	}
	return r.conf.InternalMp.ZoneDataRepo.OwnStateRead(r.zone)
}

func loadedAnswer() *EditsResponseMsg {
	return &EditsResponseMsg{SenderID: ownCombiner, Message: editsLoaded}
}

// An agent whose configuration names no combiner asks nobody for its own
// state, and says why its own read is not done.
func TestAnAgentThatNamesNoCombinerDoesNotReadItsOwnState(t *testing.T) {
	r := newReReadRigFor(t, "nocombiner.reread.example.", nil, func(_ context.Context, _ int32) (*EditsResponseMsg, error) {
		return loadedAnswer(), nil
	})
	zdr := func() *ZoneDataRepo { r.ownRead(); return r.conf.InternalMp.ZoneDataRepo }
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(zdr().ownStateWhy(r.zone), "names no combiner"); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("own read not done because %q, want that no combiner is named", zdr().ownStateWhy(r.zone))
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := r.asks.Load(); n != 0 {
		t.Errorf("the agent asked a combiner %d times, want none", n)
	}
	if r.ownRead() {
		t.Error("the own read is done without a combiner")
	}
}

// A zone whose own read is not done is read again until it is.
func TestTheOwnReadIsRepeatedUntilItSucceeds(t *testing.T) {
	r := newReReadRig(t, "repeat.reread.example.", func(_ context.Context, n int32) (*EditsResponseMsg, error) {
		if n < 3 {
			return &EditsResponseMsg{SenderID: ownCombiner, Message: editsNotLoaded}, nil
		}
		return loadedAnswer(), nil
	})
	r.waitRead(t)
	if n := r.asks.Load(); n < 3 {
		t.Errorf("read after %d requests, want the third", n)
	}
	time.Sleep(100 * time.Millisecond)
	if n := r.asks.Load(); n > 3 {
		t.Errorf("%d requests, the zone was read again after its own read was done", n)
	}
}

// The re-read waits for the zone's first load.
func TestTheOwnReadWaitsForTheZonesFirstLoad(t *testing.T) {
	r := newReReadRig(t, "firstload.reread.example.", func(context.Context, int32) (*EditsResponseMsg, error) { return loadedAnswer(), nil })
	r.mpzd.Lock()
	stub := r.mpzd.MP.MPdata
	r.mpzd.MP.MPdata = &MPdata{} // main_init's stub
	r.mpzd.Unlock()
	time.Sleep(150 * time.Millisecond)
	if n := r.asks.Load(); n != 0 {
		t.Errorf("%d requests before the zone's first load", n)
	}
	r.mpzd.Lock()
	r.mpzd.MP.MPdata = stub
	r.mpzd.Unlock()
	r.waitRead(t)
}

// The re-read never blocks the engine, one re-read per zone is in flight,
// and one that gets no answer frees its zone for the next.
func TestTheReReadDoesNotBlockTheEngine(t *testing.T) {
	release := make(chan struct{})
	r := newReReadRig(t, "blocked.reread.example.", func(ctx context.Context, n int32) (*EditsResponseMsg, error) {
		if n == 1 {
			select { // a combiner that does not answer
			case <-release:
			case <-ctx.Done():
			}
			return nil, context.DeadlineExceeded
		}
		return loadedAnswer(), nil
	})
	time.Sleep(150 * time.Millisecond) // many ticks
	start := time.Now()
	if r.ownRead() {
		t.Fatal("read while the combiner does not answer")
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("the engine took %v to answer while a re-read waited", took)
	}
	if n := r.asks.Load(); n != 1 {
		t.Errorf("%d requests in flight for one zone, want 1", n)
	}
	close(release) // the request ends with no answer, and frees the zone
	r.waitRead(t)
}

// One re-read per zone is in flight: while a request waits for its answer,
// the ticks start no other for the zone.
func TestOneReReadPerZoneIsInFlight(t *testing.T) {
	r := newReReadRig(t, "inflight.reread.example.", func(ctx context.Context, _ int32) (*EditsResponseMsg, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	time.Sleep(200 * time.Millisecond) // ten ticks
	if n := r.asks.Load(); n != 1 {
		t.Errorf("%d requests in flight for one zone, want 1", n)
	}
}

// A re-read that gets no answer frees its zone, and the next tick asks
// again.
func TestAReReadWithNoAnswerFreesItsZone(t *testing.T) {
	r := newReReadRig(t, "noanswer.reread.example.", func(_ context.Context, n int32) (*EditsResponseMsg, error) {
		if n == 1 {
			return nil, context.DeadlineExceeded
		}
		return loadedAnswer(), nil
	})
	r.waitRead(t)
	if n := r.asks.Load(); n < 2 {
		t.Errorf("read after %d requests", n)
	}
}

// A combiner whose read of its stored contributions failed at the zone's
// start reads them again when an agent asks for its own state, once the
// zone has loaded, and answers that they are loaded, with them.
func TestACombinerWhoseStartReadFailedReadsAgainWhenAsked(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "readagain.combiner.example.", false, false)
	z := mpzd.ZoneName
	ns := z + "\t3600\tIN\tNS\tns.alpha.example."
	rr, err := dns.NewRR(ns)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveContributions(hdb, z, csyncLeaderA, map[string]map[uint16]core.RRset{z: {dns.TypeNS: {RRs: []dns.RR{rr}}}}); err != nil {
		t.Fatal(err)
	}
	mpzd.Lock()
	mpzd.MP.ContributionsRead, mpzd.MP.AgentContributions = false, nil // the read at the start failed
	mpzd.Unlock()
	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.HsyncDB = hdb
	conf.SetMpConfig(&MultiProviderConf{Role: "combiner", Identity: csyncCombinerID})
	// the agent's request, as the combiner's message handler takes it (no
	// transport here: the answer is built, and not sent)
	ask := func() { sendEditsToAgent(context.Background(), conf, nil, csyncOurAgent, z, "n") }

	// not before the zone has loaded
	mpzd.Ready = false
	ask()
	if req := editsAnswerFor(mpzd, csyncCombinerID, z, "n"); req.Message != editsNotLoaded {
		t.Fatalf("before the zone loaded: %q", req.Message)
	}
	mpzd.Ready = true
	ask()
	req := editsAnswerFor(mpzd, csyncCombinerID, z, "n")
	if req.Message != editsLoaded || len(req.AgentRecords[csyncLeaderA][z]) != 1 {
		t.Errorf("after the read again: %q, %v", req.Message, req.AgentRecords)
	}
}

// A reload of the stored contributions and an update are taken one after
// the other. An update that holds the zone while the reload starts, and
// saves a newer set, is in what the reload reads: the reload does not
// roll the zone back to the set it would have read before.
func TestAReloadOfTheContributionsDoesNotRollBackAnUpdate(t *testing.T) {
	mpzd, hdb := csyncCombinerZone(t, "reload.combiner.example.", false, false)
	z := mpzd.ZoneName
	nsRR := func(name string) dns.RR {
		rr, err := dns.NewRR(z + "\t3600\tIN\tNS\t" + name)
		if err != nil {
			t.Fatal(err)
		}
		return rr
	}
	older, newer := nsRR("ns1.alpha.example."), nsRR("ns2.alpha.example.")
	if err := SaveContributions(hdb, z, csyncLeaderA, map[string]map[uint16]core.RRset{z: {dns.TypeNS: {RRs: []dns.RR{older}}}}); err != nil {
		t.Fatal(err)
	}

	// the update holds the zone as the reload starts
	mpzd.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := CombinerReapplyContributions(z, hdb)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond) // the reload has started, and waits for the zone
	mpzd.EnsureMP()
	if mpzd.MP.AgentContributions == nil {
		mpzd.MP.AgentContributions = map[string]map[string]map[uint16]core.RRset{}
	}
	mpzd.MP.AgentContributions[csyncLeaderA] = map[string]map[uint16]core.RRset{z: {dns.TypeNS: {RRs: []dns.RR{newer}}}}
	err := SaveContributions(hdb, z, csyncLeaderA, mpzd.MP.AgentContributions[csyncLeaderA])
	mpzd.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err, ok := recvWithin(done, 10*time.Second); !ok || err != nil {
		t.Fatalf("the reload: done %v, err %v", ok, err)
	}
	mpzd.Lock()
	got := mpzd.MP.AgentContributions[csyncLeaderA][z][dns.TypeNS].RRs
	mpzd.Unlock()
	if len(got) != 1 || got[0].String() != newer.String() {
		t.Errorf("after the reload the zone holds %v, want the update's %s", got, newer)
	}
}

// held is what the engine's repo holds of the agent's records of a type.
func (r *reReadRig) held(t *testing.T, agent AgentId, rrtype uint16) []string {
	t.Helper()
	resp := make(chan *SynchedDataCmdResponse, 1)
	r.msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "dump-zonedatarepo", Zone: r.zone, Response: resp}
	got, ok := recvWithin(resp, 5*time.Second)
	if !ok {
		t.Fatal("the engine did not answer")
	}
	var out []string
	for _, info := range got.ZDR[r.zone][agent][rrtype] {
		out = append(out, info.RR)
	}
	return out
}

// An older combiner's answer is applied once for the zone, at its first
// read: here the zone loads after the engine's start, and its first read is
// the re-read's. The re-reads that follow, every ownReadInterval while the
// own read is not done, apply none of its answers: an empty one clears
// nothing, and one with other records does not replace what the first
// brought.
func TestTheReReadAppliesNoAnswerOfAnOlderCombiner(t *testing.T) {
	const zone = "older.reread.example."
	ns := zone + "\t3600\tIN\tNS\tns.a.role.example."
	ns2 := zone + "\t3600\tIN\tNS\tns2.a.role.example."
	r := newReReadRig(t, zone, func(_ context.Context, n int32) (*EditsResponseMsg, error) {
		recs := map[string]map[string][]string{roleA: {zone: {ns}}}
		switch {
		case n == 1: // the zone's first read
		case n%2 == 0:
			recs = nil // an empty answer
		default:
			recs = map[string]map[string][]string{roleA: {zone: {ns2}}}
		}
		return &EditsResponseMsg{SenderID: ownCombiner, Message: "current contributions", AgentRecords: recs}, nil
	})
	for deadline := time.Now().Add(5 * time.Second); r.asks.Load() < 6; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d requests, want six", r.asks.Load())
		}
	}
	if got := r.held(t, roleA, dns.TypeNS); len(got) != 1 || got[0] != ns {
		t.Errorf("after the re-reads the repo holds %v, want the first read's %s", got, ns)
	}
	if r.ownRead() {
		t.Error("an older combiner's answer counted as the own read")
	}
}
