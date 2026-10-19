/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * tdns-mp #175: a delegation sync that goes to the parent as a NOTIFY is
 * not done when the NOTIFY has been sent. The leader looks at the parent
 * again, sends again while the parent still differs, and tells its peers
 * when the parent is in sync. And it holds the NOTIFY of a change until the
 * zone's nameservers have had time to serve it: the largest propagation
 * delay among the providers that serve the zone, which they tell each other
 * in the gossip of their beats.
 */
package tdnsmp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// fakeParent answers what the leader's analysis asks a parent server about
// the child: the NS set and the DS set it holds (which the test changes, as
// a parent that has scanned would) and the glue of the child's own
// nameserver. It also takes a DNS UPDATE over TCP and answers NOERROR
// without applying it, for the UPDATE scheme.
type fakeParent struct {
	child string
	udp   string // host:port of the parent server
	port  uint16 // TCP port of the UPDATE receiver

	mu      sync.Mutex
	ns      []string
	ds      []dns.RR
	updates int
	refuse  bool // answer an UPDATE REFUSED, as a parent that will not take it yet
}

func newFakeParent(t *testing.T, child string) *fakeParent {
	t.Helper()
	p := &fakeParent{child: child, ns: []string{"ns1." + child}}
	// port 0: the kernel picks a free port, so a port that is taken is
	// never asked for
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("the parent's UDP listener: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("the parent's TCP listener: %v", err)
	}
	p.udp = pc.LocalAddr().String()
	p.port = uint16(ln.Addr().(*net.TCPAddr).Port)
	for _, srv := range []*dns.Server{
		{PacketConn: pc, Net: "udp", Handler: dns.HandlerFunc(p.serve)},
		{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(p.serve)},
	} {
		// the server's default refuses an UPDATE before the handler sees it
		srv.MsgAcceptFunc = func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { _ = srv.ActivateAndServe() }()
		<-started
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), integTestTimeout)
			defer cancel()
			_ = srv.ShutdownContext(ctx)
		})
	}
	return p
}

func (p *fakeParent) serve(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Opcode == dns.OpcodeUpdate {
		p.updates++
		if p.refuse {
			m.Rcode = dns.RcodeRefused
		}
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	switch {
	case q.Qtype == dns.TypeNS && q.Name == p.child:
		for _, ns := range p.ns {
			m.Answer = append(m.Answer, &dns.NS{Hdr: dns.RR_Header{Name: p.child, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: ns})
		}
	case q.Qtype == dns.TypeDS && q.Name == p.child:
		m.Answer = append(m.Answer, p.ds...)
	case q.Qtype == dns.TypeA && q.Name == "ns1."+p.child:
		// the glue of the child's own nameserver, as the child has it
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: net.ParseIP("192.0.2.1")})
	}
	_ = w.WriteMsg(m)
}

// holdsNS and holdsDS set what the parent holds for the child.
func (p *fakeParent) holdsNS(ns ...string) {
	p.mu.Lock()
	p.ns = ns
	p.mu.Unlock()
}

func (p *fakeParent) holdsDS(ds ...dns.RR) {
	p.mu.Lock()
	p.ds = ds
	p.mu.Unlock()
}

// refuses has the parent answer every UPDATE REFUSED.
func (p *fakeParent) refuses() {
	p.mu.Lock()
	p.refuse = true
	p.mu.Unlock()
}

func (p *fakeParent) updatesSeen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.updates
}

// lockedBuffer is a log sink that the syncher and the timers write to while
// the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// notifyRig is the leader's side of a delegation sync as the agent runs it,
// with its surroundings: the leaderSyncRig's zone and election; the real
// DelegationSyncher on the zone's queue, with tdns's own analysis and sync;
// a parent on the loopback that the analysis queries; a resolver whose
// cache holds what the DSYNC discovery looks up; and a second provider's
// agent, reached over the wire, that hears what the leader tells its peers.
// What tdns hands the notifier arrives on notifyq; nothing sends it on.
type notifyRig struct {
	*leaderSyncRig
	parent  *fakeParent
	us      *peerEnv // the leader's own transport and registry
	peer    *peerEnv
	notifyq chan tdns.NotifyRequest
	log     *lockedBuffer
	ksk     KeyInventoryItem // the zone's KSK, as its signer reports it
	ds      dns.RR           // the DS of that key
	oldNS   string           // a nameserver the zone no longer lists
}

// newNotifyRig starts the rig for a zone whose parent advertises the given
// DSYNC scheme ("NOTIFY" or "UPDATE"). The parent starts in sync with the
// zone. delays replaces delegationSyncNotifyDelays. The agent announces no
// propagation delay, so no NOTIFY is held, until propagation sets one.
func newNotifyRig(t *testing.T, zone, scheme string, delays ...time.Duration) *notifyRig {
	t.Helper()
	return newNotifyRigFor(t, zone, scheme, false, delays...)
}

// newNotifyRigFor is the rig for a zone that no provider signs, as the tests
// of the hold and the checks have it, or for a signed one: both providers
// sign it. For a signed zone the leader makes the zone's CSYNC, so the rig
// then also runs the leader's data engine, which distributes it
// (mp_s5_leader_csync_test.go has what stands in for the providers).
func newNotifyRigFor(t *testing.T, zone, scheme string, signed bool, delays ...time.Duration) *notifyRig {
	t.Helper()
	savedDelays, savedLog := delegationSyncNotifyDelays, lgEngine
	logsink := &lockedBuffer{}
	delegationSyncNotifyDelays = delays
	lgEngine = slog.New(slog.NewTextHandler(logsink, nil))
	// registered first, so run last: after the syncher has stopped and what
	// it scheduled has ended (waitDelegationSyncTimers)
	t.Cleanup(func() { delegationSyncNotifyDelays, lgEngine = savedDelays, savedLog })
	installParentSync(t, fmt.Sprintf(parentSyncConfig, "ED25519"))

	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	us, them := env.Alice, env.Bob
	r := &notifyRig{leaderSyncRig: newLeaderSyncRigAs(t, zone, AgentId(us.Identity)), us: us, peer: them,
		notifyq: make(chan tdns.NotifyRequest, 64), log: logsink, oldNS: "gone.provider.example."}
	r.leader(AgentId(us.Identity))
	r.conf.InternalMp.MPTransport = us.Bridge
	r.conf.InternalMp.AgentRegistry.GossipStateTable = us.Registry.GossipStateTable
	tdns.RegisterKeyLifecycleOwner(r.conf.InternalMp.KeyLifecycleOwner)
	t.Cleanup(func() { tdns.RegisterKeyLifecycleOwner(nil) })

	// The leader is an agent: it signs nothing, and its copy of the zone is
	// the signed zone as the signer serves it, with the DNSKEY RRset, the
	// CDS and the providers' HSYNC records.
	yes := true
	r.ksk = invItem(t, zone, 257, KeyStateActive, &yes)
	key, err := dns.NewRR(r.ksk.KeyRR)
	if err != nil {
		t.Fatalf("the KSK: %v", err)
	}
	ds := key.(*dns.DNSKEY).ToDS(dns.SHA256)
	r.ds = ds
	zd := r.mpzd.ZoneData
	zd.Options[tdns.OptInlineSigning] = false
	apex, err := r.mpzd.OwnerForAnalysis(zone)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: zone, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600}
	}
	apex.RRtypes.Set(dns.TypeDNSKEY, core_RRset(key))
	apex.RRtypes.Set(dns.TypeCDS, core_RRset(ds.ToCDS()))
	var h3s []dns.RR
	var labels []string
	for _, id := range []string{us.Identity, them.Identity} {
		labels = append(labels, shortLabel(id))
		h3s = append(h3s, &dns.PrivateRR{Hdr: hdr(core.TypeHSYNC3), Data: &core.HSYNC3{State: 1, Label: shortLabel(id), Identity: id, Upstream: "."}})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: h3s})
	roles := []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMServers{Servers: labels}}
	if signed {
		roles = append(roles, &core.HSYNCPARAMSigners{Signers: labels})
	}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNCPARAM),
		Data: &core.HSYNCPARAM{Value: roles}}}})
	r.mpzd.Data.Set(zone, *apex)
	zd.InstallInitialSnapshot() // the analysis reads the zone as it is served
	zd.Ready = true

	// the peer: the other provider's agent, listening on the loopback
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("the peer's listener: %v", err)
	}
	them.Registry.S.Set(AgentId(us.Identity), NewAgent(AgentId(us.Identity)))
	them.Bridge.PeerRegistry.GetOrCreate(us.Identity)
	them.Bridge.StartIncomingMessageRouter(env.ctx)
	serveDNS(t, env.ctx, ln, them)
	if err := us.Bridge.PeerRegistry.Add(peerFromAddress(them.Identity, ln.Addr().String())); err != nil {
		t.Fatalf("the peer: %v", err)
	}

	// what the analysis needs of the parent, without a resolver: its name
	// and where its servers are
	zlabels := dns.SplitDomainName(zone)
	parentZone := dns.Fqdn(strings.Join(zlabels[1:], "."))
	r.parent = newFakeParent(t, zone)
	r.parent.holdsDS(ds)
	zd.SetParent(parentZone)
	zd.ParentNS = []string{"ns." + parentZone}
	zd.ParentServers = []string{r.parent.udp}

	// what the DSYNC discovery and the target lookup ask the resolver for
	imr := &tdns.Imr{Cache: cache.NewRRsetCache(log.New(io.Discard, "", 0), false, false)}
	target := "dsync." + parentZone
	cached := func(name string, rrtype uint16, rrs ...dns.RR) {
		c := &cache.CachedRRset{Name: name, RRtype: rrtype, Context: cache.ContextNoErrNoAns,
			State: cache.ValidationStateSecure, Ttl: 3600, Expiration: time.Now().Add(time.Hour)}
		if len(rrs) > 0 {
			c.Context = cache.ContextAnswer
			c.RRset = &core.RRset{Name: name, Class: dns.ClassINET, RRtype: rrtype, RRs: rrs}
		}
		imr.Cache.Set(name, rrtype, c)
	}
	dsyncName := zlabels[0] + "._dsync." + parentZone
	var dsync []dns.RR
	for _, rdata := range map[string][]string{"NOTIFY": {"CDS NOTIFY", "CSYNC NOTIFY"}, "UPDATE": {"ANY UPDATE"}}[scheme] {
		rr, err := dns.NewRR(fmt.Sprintf("%s 3600 IN DSYNC %s %d %s", dsyncName, rdata, r.parent.port, target))
		if err != nil {
			t.Fatalf("the DSYNC record: %v", err)
		}
		dsync = append(dsync, rr)
	}
	cached(dsyncName, core.TypeDSYNC, dsync...)
	cached(target, dns.TypeA, &dns.A{Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: net.ParseIP("127.0.0.1")})
	cached(target, dns.TypeAAAA)
	r.conf.Config.Internal.ImrEngine = imr

	// the syncher, and the DS engine it asks for the CDS before a NOTIFY(CDS),
	// on the rig's ctx, which ends with the test
	ctx := r.ctx
	ensureDSEngineQueue(zd.KeyDB)
	var engines sync.WaitGroup
	if signed {
		r.startDataEngine(t, ctx, &engines)
	}
	engines.Add(2)
	go func() {
		defer engines.Done()
		_ = zd.KeyDB.DSEngine(ctx)
	}()
	go func() {
		defer engines.Done()
		_ = (&HsyncDB{KeyDB: zd.KeyDB}).DelegationSyncher(ctx, r.q, r.notifyq, r.conf)
	}()
	t.Cleanup(func() {
		stopped := make(chan struct{})
		go func() { engines.Wait(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Error("the delegation syncher and the DS engine did not stop")
		}
	})
	return r
}

// propagation sets this provider's propagation delay, as the agent's start
// does from dnssec.kasp.propagation-delay.
func (r *notifyRig) propagation(d time.Duration) {
	r.conf.InternalMp.AgentRegistry.GossipStateTable.SetPropagationDelay(d)
}

// inventory is the signer's word on the zone's keys, as the agent's engine
// handles it: a DS set that is not what it was asks for a sync.
func (r *notifyRig) inventory(items ...KeyInventoryItem) {
	r.e.handleKeystateInventory(r.ctx, r.lem.localID, &KeystateInventoryMsg{SenderID: "signer.alice.example.", Zone: r.mpzd.ZoneName,
		Inventory: items, Owned: true}, r.sdq, nil)
}

// hint is the combiner's word that the zone's NS set changed, as the
// agent's engine handles it.
func (r *notifyRig) hint() {
	r.e.handleStatusUpdate(r.ctx, &StatusUpdateMsg{Zone: r.mpzd.ZoneName, SubType: "ns-changed"})
}

// notified waits for one sync's NOTIFYs to reach the notifier, in order.
func (r *notifyRig) notified(t *testing.T, what string, rrtypes ...uint16) {
	t.Helper()
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(r.parent.port)))
	for _, rrtype := range rrtypes {
		select {
		case req := <-r.notifyq:
			if req.ZoneName != r.mpzd.ZoneName || req.RRtype != rrtype || len(req.Targets) != 1 || req.Targets[0] != target {
				t.Fatalf("%s: NOTIFY(%s) for %s to %v, want NOTIFY(%s) to %s\n%s", what,
					dns.TypeToString[req.RRtype], req.ZoneName, req.Targets, dns.TypeToString[rrtype], target, r.log)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: no NOTIFY(%s) was handed to the notifier\n%s", what, dns.TypeToString[rrtype], r.log)
		}
	}
}

// quiet: no NOTIFY is waiting for the notifier once the given time has
// passed. drain first takes those a sync sent before the test looked away.
func (r *notifyRig) quiet(t *testing.T, d time.Duration, what string) {
	t.Helper()
	time.Sleep(d)
	select {
	case req := <-r.notifyq:
		t.Errorf("%s: NOTIFY(%s) was sent\n%s", what, dns.TypeToString[req.RRtype], r.log)
	default:
	}
}

func (r *notifyRig) drain() {
	for {
		select {
		case <-r.notifyq:
		default:
			return
		}
	}
}

// told waits for the peer to hear that the parent sync is done.
func (r *notifyRig) told(t *testing.T, what string) *StatusUpdateMsg {
	t.Helper()
	m, ok := recvWithin(r.peer.MsgQs.StatusUpdate, 10*time.Second)
	if !ok {
		t.Fatalf("%s: the peer was not told that the parent sync is done\n%s", what, r.log)
	}
	if m.SubType != "parentsync-done" || m.Zone != r.mpzd.ZoneName || m.Result != "NOERROR" {
		t.Errorf("%s: the peer was told %+v", what, *m)
	}
	return m
}

// untold: the peer has heard nothing once the given time has passed.
func (r *notifyRig) untold(t *testing.T, d time.Duration, what string) {
	t.Helper()
	time.Sleep(d)
	select {
	case m := <-r.peer.MsgQs.StatusUpdate:
		t.Errorf("%s: the peer was told %q (%s)\n%s", what, m.SubType, m.Msg, r.log)
	default:
	}
}

// chains is the number of zones the leader keeps a chain for.
func (r *notifyRig) chains() int {
	c := &r.conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.zones)
}

// logged waits until the engine's log has the text n times, and fails if
// it has it more often.
func (r *notifyRig) logged(t *testing.T, n int, text string) {
	t.Helper()
	got := 0
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if got = strings.Count(r.log.String(), text); got >= n {
			break
		}
	}
	if got != n {
		t.Errorf("the engine logged %q %d times, want %d\n%s", text, got, n, r.log)
	}
}

const (
	logHeld       = `msg="a NOTIFY to the parent is held until the zone's nameservers have had time to serve the change"`
	logLeft       = `msg="the held NOTIFY has left for the parent"`
	logDropped    = `msg="the held NOTIFY is dropped: this agent no longer leads the zone"`
	logNotNeeded  = `msg="the held NOTIFY is dropped: the parent does not need it any more"`
	logCheckAgain = `msg="the delegation sync went to the parent as a NOTIFY; checking the parent again"`
	logCheckAsked = `msg="delegation sync requested" zone=%s why="a NOTIFY was sent to the parent, which is checked again"`
	logInSync     = `msg="the parent is in sync with the zone after the NOTIFY"`
	logGivenUp    = `msg="the parent still differs from the zone after the last check, and a last NOTIFY has been sent; given up until the delegation's data changes or an election is held"`
)

// What a test fleet showed: the signer creates the CDS and tells its agent,
// the leader, which sends NOTIFY(CDS) at once. The parent scans before any
// nameserver serves the CDS and finds nothing to do. The sync counted as
// done, the peers were told so, and nothing asked again: the parent stayed
// without the DS.
func TestANotifiedSyncIsNotDoneUntilTheParentIsInSync(t *testing.T) {
	r := newNotifyRig(t, "early.notify.example.", "NOTIFY", repeat(50*time.Millisecond, 400)...)
	z := r.mpzd.ZoneName
	r.parent.holdsDS() // the parent has no DS yet

	// the signer's inventory, with the KSK's DS wanted at the parent, is what
	// asks for the sync
	r.inventory(r.ksk)
	r.notified(t, "the first sync", dns.TypeCDS)
	// the parent does not have the DS: the leader looks again, and sends again
	r.notified(t, "the first check", dns.TypeCDS)
	r.notified(t, "the second check", dns.TypeCDS)
	r.logged(t, 1, logCheckAgain+" zone="+z+" notify=CDS check=1 in=50ms")
	r.logged(t, 1, logCheckAgain+" zone="+z+" notify=CDS check=2 in=50ms")
	// three NOTIFYs have gone, and none of them made the sync done
	r.untold(t, 100*time.Millisecond, "while the parent still differed")

	// the parent scans and installs the DS: the next check finds it, the
	// chain ends, and the peer is told, once
	r.parent.holdsDS(r.ds)
	if m := r.told(t, "the parent in sync"); m.SenderID != string(r.lem.localID) || !strings.Contains(m.Msg, "after NOTIFY(CDS)") {
		t.Errorf("the peer was told %+v", *m)
	}
	r.logged(t, 1, logInSync)
	r.drain()
	r.quiet(t, 300*time.Millisecond, "after the parent was found in sync")
	r.untold(t, 0, "a second time")
	if n := r.chains(); n != 0 {
		t.Errorf("%d chains left after the parent was found in sync", n)
	}
}

func repeat(d time.Duration, n int) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = d
	}
	return out
}

// An UPDATE's answer is the parent's: the sync is done when it has come, the
// peers are told at once, and nothing looks at the parent again. Nor is an
// UPDATE held back: the wait before a NOTIFY is for the parent's scan of the
// zone's nameservers, and an UPDATE carries the change itself.
func TestAnUpdateIsDoneWhenTheParentHasAnswered(t *testing.T) {
	r := newNotifyRig(t, "update.notify.example.", "UPDATE", repeat(30*time.Millisecond, 400)...)
	r.propagation(time.Hour)
	z := r.mpzd.ZoneName
	if _, err := r.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	// the parent takes the UPDATE and goes on listing the old nameserver:
	// if anything looked again, it would send again
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.hint()
	if m := r.told(t, "the UPDATE answered"); !strings.Contains(m.Msg, "SendUpdate(") {
		t.Errorf("the peer was told %+v", *m)
	}
	time.Sleep(300 * time.Millisecond) // ten times the first delay
	if n := r.parent.updatesSeen(); n != 1 {
		t.Errorf("the parent got %d UPDATEs, want the one", n)
	}
	r.quiet(t, 0, "by the UPDATE scheme")
	r.untold(t, 0, "a second time")
	if l := r.log.String(); strings.Contains(l, logCheckAgain) || strings.Contains(l, "which is checked again") || strings.Contains(l, logHeld) {
		t.Errorf("a sync sent as an UPDATE was held, or checked again:\n%s", l)
	}
}

// The second trigger of an NS change, the agent's own refresh, sends what
// the refresh found without an analysis. Its NOTIFY is checked like any
// other.
func TestTheNotifyOfARefreshIsCheckedToo(t *testing.T) {
	r := newNotifyRig(t, "refresh.notify.example.", "NOTIFY", repeat(50*time.Millisecond, 400)...)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)

	changed, dss, err := implicitDelegationChange(r.mpzd, refreshedZone(t, r.mpzd, fmt.Sprintf("%s 3600 IN NS ns2.provider.example.", z)))
	if err != nil || !changed {
		t.Fatalf("the refresh: changed=%v err=%v", changed, err)
	}
	r.mpzd.EnsureMP()
	r.mpzd.MP.RefreshAnalysis = &ZoneRefreshAnalysis{DelegationChanged: changed, DelegationStatus: dss}
	r.mpzd.PostRefresh(nil, nil)

	r.notified(t, "the refresh's sync", dns.TypeCSYNC)
	r.notified(t, "the first check", dns.TypeCSYNC)
	r.untold(t, 100*time.Millisecond, "while the parent still differed")
	r.parent.holdsNS("ns1." + z)
	if m := r.told(t, "the parent in sync"); !strings.Contains(m.Msg, "after NOTIFY(CSYNC)") {
		t.Errorf("the peer was told %+v", *m)
	}
	r.drain()
	r.quiet(t, 300*time.Millisecond, "after the parent was found in sync")
	r.untold(t, 0, "a second time")
}

// The check is the leader's. An agent that lost the leadership while its
// check waited asks for nothing, and its chain is over: the next NOTIFY it
// sends as the leader starts from the first delay.
func TestLosingTheLeadershipEndsTheChecksOfANotify(t *testing.T) {
	const delay = 300 * time.Millisecond
	r := newNotifyRig(t, "lost.notify.example.", "NOTIFY", delay, time.Hour)
	z := r.mpzd.ZoneName
	us := r.lem.localID
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.hint()
	r.notified(t, "the first sync", dns.TypeCSYNC)
	r.leader(AgentId(r.peer.Identity)) // before the check comes due
	r.logged(t, 1, logCheckAgain)
	r.quiet(t, delay+500*time.Millisecond, "by an agent that lost the leadership")
	r.leader(us)
	r.quiet(t, 200*time.Millisecond, "by a chain that had ended")
	r.untold(t, 0, "by an agent whose chain had ended")
	if n := r.chains(); n != 0 {
		t.Errorf("%d chains left after the leadership was lost", n)
	}

	r.hint()
	r.notified(t, "leading again", dns.TypeCSYNC)
	r.logged(t, 2, logCheckAgain+" zone="+z+" notify=CSYNC check=1 in=300ms")
}

// The parent never catches up: the checks end at the bound, with a warning
// and no word to the peers, and the next change starts a new chain. Here
// both the NS set and the DS set differ, so a sync sends two NOTIFYs.
func TestTheChecksOfANotifyAreBounded(t *testing.T) {
	yes := true
	r := newNotifyRig(t, "bound.notify.example.", "NOTIFY", 30*time.Millisecond, 30*time.Millisecond)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.parent.holdsDS()
	r.inventory(r.ksk)
	r.notified(t, "the first sync", dns.TypeCSYNC, dns.TypeCDS)
	r.notified(t, "the first check", dns.TypeCSYNC, dns.TypeCDS)
	r.notified(t, "the second check", dns.TypeCSYNC, dns.TypeCDS)
	r.logged(t, 1, logGivenUp+" zone="+z+` notify="CSYNC, CDS" checks=2`)
	r.quiet(t, 300*time.Millisecond, "past the bound")
	r.untold(t, 0, "by a chain that was given up")
	r.logged(t, 2, logCheckAgain)
	if n := r.chains(); n != 0 {
		t.Errorf("%d chains left past the bound", n)
	}

	// given up means forgotten: the next change of the DS set is the first
	// NOTIFY of a new chain
	next := invItem(t, z, 257, KeyStateStandby, &yes)
	r.inventory(r.ksk, next)
	r.notified(t, "the next change", dns.TypeCSYNC, dns.TypeCDS)
	r.logged(t, 2, logCheckAgain+" zone="+z+` notify="CSYNC, CDS" check=1 in=30ms`)
}

// A second trigger while a check waits (the two that one NS change brings,
// a new change, an election) sends its own NOTIFY and starts no second
// chain: one check follows the two NOTIFYs, and one word to the peer.
func TestASecondAskWhileACheckWaitsStartsNoSecondChain(t *testing.T) {
	const delay = 600 * time.Millisecond
	r := newNotifyRig(t, "twice.notify.example.", "NOTIFY", repeat(delay, 400)...)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	// both are on the syncher's queue before it has sent for the first
	r.hint()
	if !r.conf.requestDelegationSync(r.ctx, z, "this agent was elected the zone's delegation sync leader") {
		t.Fatal("the second request was not queued")
	}
	r.notified(t, "the first trigger", dns.TypeCSYNC)
	r.notified(t, "the second trigger", dns.TypeCSYNC)
	// the parent catches up before any check comes due
	r.parent.holdsNS("ns1." + z)
	// the check that waited for the first NOTIFY was replaced by one timed
	// for the second
	r.logged(t, 2, logCheckAgain+" zone="+z+" notify=CSYNC check=1 in=600ms")
	if n := r.chains(); n != 1 {
		t.Errorf("%d chains for one zone", n)
	}
	// one check finds the parent in sync, and the peer is told once
	r.told(t, "the parent in sync")
	r.logged(t, 1, logInSync)
	r.untold(t, delay+300*time.Millisecond, "a second time") // past any second check
	if n := strings.Count(r.log.String(), fmt.Sprintf(logCheckAsked, z)); n != 1 {
		t.Errorf("%d checks were asked for after two NOTIFYs, want one\n%s", n, r.log)
	}
	r.quiet(t, 0, "by a second chain")
	if n := r.chains(); n != 0 {
		t.Errorf("%d chains left after the parent was found in sync", n)
	}
}

// The two chains are one: a NOTIFY and a failure keep their own counts in
// the zone's one entry, and there is never more than one ask waiting.
func TestAFailedAndANotifiedSyncShareOneChain(t *testing.T) {
	r := newLeaderSyncRig(t, "shared.sync.example.")
	z := r.mpzd.ZoneName
	r.leader("agent.us.example.")
	ctx := r.ctx
	chains := &r.conf.InternalMp.delegationSyncChains
	chain := func() (ch delegationSyncChain, n int) {
		chains.mu.Lock()
		defer chains.mu.Unlock()
		if c := chains.zones[z]; c != nil {
			ch = *c
		}
		return ch, len(chains.zones)
	}
	short, long := repeat(20*time.Millisecond, 8), repeat(300*time.Millisecond, 8)
	refused := errors.New("refused")
	// what a sync handed over for the notifier, with no wait before it leaves
	cds := delegationNotifies{requests: []tdns.NotifyRequest{{ZoneName: z, RRtype: dns.TypeCDS}}}
	csync := delegationNotifies{requests: []tdns.NotifyRequest{{ZoneName: z, RRtype: dns.TypeCSYNC}}}

	// a check's own sync fails: the failure asks again by its own delays,
	// and the NOTIFY is not forgotten
	r.conf.delegationSyncNotifiedWith(ctx, z, cds, short)
	if n := r.waitRequests(t, 1, 2*time.Second); n != 1 {
		t.Fatalf("after a NOTIFY: %d sync requests, want 1", n)
	}
	r.conf.delegationSyncFailedWith(ctx, z, refused, short)
	if n := r.waitRequests(t, 1, 2*time.Second); n != 1 {
		t.Fatalf("after the check's sync failed: %d sync requests, want 1", n)
	}
	if ch, _ := chain(); ch.notified != "CDS" || ch.rechecks != 1 || ch.failures != 1 || ch.waiting {
		t.Errorf("the chain after a NOTIFY and a failure: %+v", ch)
	}
	// the retry sends: the failures are over, the checks go on where they were
	r.conf.delegationSyncNotifiedWith(ctx, z, cds, short)
	if ch, _ := chain(); ch.rechecks != 2 || ch.failures != 0 {
		t.Errorf("the chain after the retry sent its NOTIFY: %+v", ch)
	}
	if n := r.waitRequests(t, 1, 2*time.Second); n != 1 {
		t.Fatalf("after the second NOTIFY: %d sync requests, want 1", n)
	}
	// the parent is found in sync: the caller learns what the chain had sent
	if sent, checks := r.conf.delegationSyncSucceeded(z); sent != "CDS" || checks != 2 {
		t.Errorf("the chain ended with notify %q after %d checks, want CDS after 2", sent, checks)
	}
	if sent, _ := r.conf.delegationSyncSucceeded(z); sent != "" {
		t.Errorf("a chain that had ended still says it sent %q", sent)
	}

	// a retry of a failed sync waits, and something else's sync sends a
	// NOTIFY: its check replaces the retry, which then asks for nothing
	r.conf.delegationSyncFailedWith(ctx, z, refused, long)
	r.conf.delegationSyncNotifiedWith(ctx, z, csync, short)
	if ch, _ := chain(); ch.notified != "CSYNC" || ch.rechecks != 1 || ch.failures != 0 {
		t.Errorf("the chain after a NOTIFY while a retry waited: %+v", ch)
	}
	if n := r.waitRequests(t, 1, 2*time.Second); n != 1 {
		t.Fatalf("the check that replaced the retry: %d sync requests, want 1", n)
	}
	time.Sleep(400 * time.Millisecond) // past the retry's own delay
	if n := r.requests(t); n != 0 {
		t.Errorf("the replaced retry asked for %d syncs", n)
	}
	// a check waits, and something else's sync fails: the check that waits
	// is the retry, and no second ask is scheduled
	r.conf.delegationSyncNotifiedWith(ctx, z, csync, long)
	r.conf.delegationSyncFailedWith(ctx, z, refused, short)
	if ch, _ := chain(); ch.failures != 0 || ch.rechecks != 2 || !ch.waiting {
		t.Errorf("the chain after a failure while a check waited: %+v", ch)
	}
	if n := r.waitRequests(t, 1, 2*time.Second); n != 1 {
		t.Fatalf("the check that waited: %d sync requests, want 1", n)
	}
	time.Sleep(100 * time.Millisecond) // past the failure's delay
	if n := r.requests(t); n != 0 {
		t.Errorf("a failure while a check waited asked for %d more syncs", n)
	}
	// a check waits, and something else's sync sends a NOTIFY: the check is
	// timed anew, for this NOTIFY, and is still the same check
	r.conf.delegationSyncNotifiedWith(ctx, z, csync, long)
	r.conf.delegationSyncNotifiedWith(ctx, z, cds, short)
	if ch, _ := chain(); ch.notified != "CDS" || ch.rechecks != 3 {
		t.Errorf("the chain after a NOTIFY while a check waited: %+v", ch)
	}
	if n := r.waitRequests(t, 1, 2*time.Second); n != 1 {
		t.Fatalf("the check timed anew: %d sync requests, want 1", n)
	}
	time.Sleep(400 * time.Millisecond) // past the delay the check had before
	if n := r.requests(t); n != 0 {
		t.Errorf("the check asked for %d more syncs at its old time", n)
	}
	// the parent is found in sync while an ask waits: the chain is emptied,
	// and the ask that fires finds nothing to go on with
	r.conf.delegationSyncNotifiedWith(ctx, z, csync, long)
	if sent, checks := r.conf.delegationSyncSucceeded(z); sent != "CSYNC" || checks != 4 {
		t.Errorf("the chain ended with notify %q after %d checks, want CSYNC after 4", sent, checks)
	}
	if ch, _ := chain(); ch.notified != "" || ch.rechecks != 0 || !ch.waiting {
		t.Errorf("the chain that ended while its ask waited: %+v", ch)
	}
	if n := r.waitRequests(t, 1, 2*time.Second); n != 1 {
		t.Fatalf("the ask that waited when the chain ended: %d sync requests, want 1", n)
	}
	if sent, _ := r.conf.delegationSyncSucceeded(z); sent != "" {
		t.Errorf("the emptied chain says it sent %q", sent)
	}
	if _, n := chain(); n != 0 {
		t.Errorf("%d chains left", n)
	}

	// a trigger that comes again while a check waits (an election, at every
	// renewal of the lease) does not keep the chain from its bound: two
	// delays are two checks, however many NOTIFYs came in between
	short, long = short[:2], long[:2]
	for check := 1; check <= 2; check++ {
		r.conf.delegationSyncNotifiedWith(ctx, z, cds, long)  // the chain's own
		r.conf.delegationSyncNotifiedWith(ctx, z, cds, short) // something else's, while the check waits
		if ch, _ := chain(); ch.rechecks != check {
			t.Errorf("check %d: the chain counts %d", check, ch.rechecks)
		}
		if n := r.waitRequests(t, 1, 2*time.Second); n != 1 {
			t.Fatalf("check %d: %d sync requests, want 1", check, n)
		}
	}
	r.conf.delegationSyncNotifiedWith(ctx, z, cds, short)
	if _, n := chain(); n != 0 {
		t.Errorf("past the bound %d chains are left", n)
	}
	time.Sleep(400 * time.Millisecond)
	if n := r.requests(t); n != 0 {
		t.Errorf("past the bound %d syncs were asked for", n)
	}
}

// A zone the agent runs alone (its identity zone) has its own loop and no
// election to ask through. Its NOTIFY goes to the notifier as it always
// did: not held, not checked.
func TestAZoneThatIsNotMultiProviderIsNeitherHeldNorChecked(t *testing.T) {
	r := newNotifyRig(t, "alone.notify.example.", "NOTIFY", repeat(50*time.Millisecond, 400)...)
	r.propagation(time.Hour)
	z := r.mpzd.ZoneName
	r.mpzd.Options[tdns.OptMultiProvider] = false
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.hint()
	r.notified(t, "the sync", dns.TypeCSYNC) // at once: the rig waits ten seconds, not the hour
	if m := r.told(t, "when the NOTIFY was sent"); !strings.Contains(m.Msg, "Sent NOTIFY(CSYNC)") {
		t.Errorf("the peer was told %+v", *m)
	}
	r.quiet(t, 300*time.Millisecond, "by a check")
	if l := r.log.String(); strings.Contains(l, logHeld) || strings.Contains(l, logCheckAgain) || r.chains() != 0 {
		t.Errorf("a zone that is not multi-provider was held, or put on the leader's chain (%d chains):\n%s", r.chains(), l)
	}
}

// The leader does not send the NOTIFY of a change at once. The zone's
// nameservers need time to serve the change, and a parent that scans before
// they do finds nothing. The NOTIFY is held for the zone's wait; the first
// check is timed from when it leaves; and the chain's own checks send at
// once, since the change is old by then.
func TestANotifyIsHeldForTheZonesWaitAndCheckedFromWhenItLeaves(t *testing.T) {
	const wait, delay = 400 * time.Millisecond, 300 * time.Millisecond
	r := newNotifyRig(t, "held.notify.example.", "NOTIFY", repeat(delay, 400)...)
	r.propagation(wait)
	z := r.mpzd.ZoneName
	r.parent.holdsDS() // the parent has no DS yet

	changed := time.Now()
	r.inventory(r.ksk)
	r.notified(t, "the held NOTIFY", dns.TypeCDS)
	if d := time.Since(changed); d < wait {
		t.Errorf("the NOTIFY left %s after the change, want it held for %s", d, wait)
	}
	r.untold(t, 0, "while the NOTIFY was held")
	// the first check: the wait and the first delay after the change
	r.notified(t, "the first check", dns.TypeCDS)
	if d := time.Since(changed); d < wait+delay {
		t.Errorf("the first check sent %s after the change, want the wait and the first delay: %s", d, wait+delay)
	}
	r.logged(t, 1, logHeld+" zone="+z+" notify=CDS wait=400ms largest="+string(r.lem.localID))
	r.logged(t, 1, logLeft+" zone="+z+" notify=CDS held=400ms")
	r.logged(t, 1, logCheckAgain+" zone="+z+" notify=CDS check=1 in=300ms")
	// the checks' own NOTIFYs were not held
	r.notified(t, "the second check", dns.TypeCDS)
	r.logged(t, 1, logHeld)
	r.logged(t, 1, logLeft)
	r.parent.holdsDS(r.ds)
	r.told(t, "the parent in sync")
	r.logged(t, 1, logInSync)
	r.untold(t, 0, "a second time")
}

// The data changes again while a NOTIFY is held: the held one is replaced,
// one per type, and the wait starts anew. The nameservers need the wait
// from the last change.
func TestAChangeDuringAHoldReplacesTheHeldNotifyAndStartsTheWaitAnew(t *testing.T) {
	const wait = time.Second
	r := newNotifyRig(t, "again.notify.example.", "NOTIFY", repeat(time.Minute, 4)...)
	r.propagation(wait)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.parent.holdsDS()

	// the NS set changed: NOTIFY(CSYNC), held
	r.hint()
	r.logged(t, 1, logHeld+" zone="+z+" notify=CSYNC wait=1s")
	// the DS set changes while that waits: the sync finds both differing now
	again := time.Now()
	r.inventory(r.ksk)
	r.logged(t, 1, logHeld+" zone="+z+` notify="CSYNC, CDS" wait=1s`)
	r.notified(t, "after the second change", dns.TypeCSYNC, dns.TypeCDS)
	if d := time.Since(again); d < wait {
		t.Errorf("the NOTIFYs left %s after the second change, want the wait from there: %s", d, wait)
	}
	r.logged(t, 1, logLeft+" zone="+z+` notify="CSYNC, CDS" held=1s`)
	// the NOTIFY(CSYNC) that was held first did not leave as well
	r.quiet(t, 300*time.Millisecond, "for the change that was replaced")
	r.untold(t, 0, "before the parent was in sync")
	if n := r.chains(); n != 1 {
		t.Errorf("%d chains for one zone", n)
	}
}

// A sync that finds what the held NOTIFY is already for brings no change: an
// election, an operator's request. It does not start the wait anew: where
// such syncs come more often than the wait is long, the NOTIFY would never
// leave.
func TestASyncThatFindsTheSameDifferenceDoesNotStartTheWaitAnew(t *testing.T) {
	const wait = time.Second
	r := newNotifyRig(t, "same.notify.example.", "NOTIFY", repeat(time.Minute, 4)...)
	r.propagation(wait)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.hint()
	r.logged(t, 1, logHeld)
	if !r.conf.requestDelegationSync(r.ctx, z, "this agent was elected the zone's delegation sync leader") {
		t.Fatal("the election's request was not queued")
	}
	// the operator's request, as the API makes it, is answered that the
	// NOTIFY waits
	answer := make(chan tdns.DelegationSyncStatus, 1)
	r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: z, ZoneData: r.mpzd.ZoneData, Response: answer}
	if st, ok := recvWithin(answer, 10*time.Second); !ok || st.Error || !strings.Contains(st.Msg, "Sent NOTIFY(CSYNC)") || !strings.Contains(st.Msg, "(held: ") {
		t.Errorf("the operator's request was answered %q (error %v, answered %v)", st.Msg, st.Error, ok)
	}
	r.notified(t, "the held NOTIFY", dns.TypeCSYNC)
	r.logged(t, 1, logLeft)
	r.quiet(t, 300*time.Millisecond, "for each of the syncs")
	r.logged(t, 1, logHeld)
}

// The leadership moves while a NOTIFY is held: it is the new leader's to
// send. The held one is dropped, and the chain is over.
func TestLosingTheLeadershipDuringAHoldDropsTheNotify(t *testing.T) {
	const wait = time.Second
	r := newNotifyRig(t, "moved.notify.example.", "NOTIFY", repeat(50*time.Millisecond, 400)...)
	r.propagation(wait)
	z := r.mpzd.ZoneName
	us := r.lem.localID
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.hint()
	r.logged(t, 1, logHeld)
	r.leader(AgentId(r.peer.Identity)) // before the wait is over
	r.logged(t, 1, logDropped+" zone="+z+" notify=CSYNC")
	if n := r.chains(); n != 0 {
		t.Errorf("%d chains left after the held NOTIFY was dropped", n)
	}
	r.leader(us)
	r.quiet(t, 300*time.Millisecond, "by an agent that lost the leadership while it held it")
	r.untold(t, 0, "by an agent whose chain had ended")
	if l := r.log.String(); strings.Contains(l, logLeft) || strings.Contains(l, logCheckAgain) {
		t.Errorf("a NOTIFY that was dropped left, or was checked:\n%s", l)
	}
}

// The parent catches up by itself while a NOTIFY is held (its own scan):
// the next analysis finds it in sync, and what is held has nothing left to
// tell it. Nothing was sent, so the peers are told nothing.
func TestAParentFoundInSyncDuringAHoldNeedsNoNotify(t *testing.T) {
	const wait = time.Second
	r := newNotifyRig(t, "caught.notify.example.", "NOTIFY", repeat(50*time.Millisecond, 400)...)
	r.propagation(wait)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.hint()
	r.logged(t, 1, logHeld)
	r.parent.holdsNS("ns1." + z)
	if !r.conf.requestDelegationSync(r.ctx, z, "this agent was elected the zone's delegation sync leader") {
		t.Fatal("the request was not queued")
	}
	r.logged(t, 1, logNotNeeded+" zone="+z+" notify=CSYNC")
	r.quiet(t, wait+300*time.Millisecond, "although the parent was in sync")
	r.untold(t, 0, "of a sync that sent nothing")
	if n := r.chains(); n != 0 {
		t.Errorf("%d chains left", n)
	}
}

// A provider's propagation delay reaches the other providers' agents in the
// gossip of its beats, and is merged there as its beat interval is. An agent
// that announces none is not known.
func TestThePropagationDelayIsAnnouncedInTheBeatsGossip(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	alice, bob := env.Alice, env.Bob
	zd := seedZoneWithHSYNC3(t, "gossip.notify.example.", alice.Identity, bob.Identity)
	addHSYNCPARAMServers(t, zd, shortLabel(alice.Identity), shortLabel(bob.Identity))
	alice.Registry.GossipStateTable.SetPropagationDelay(7 * time.Minute) // bob sets none
	var group string
	for _, p := range []*peerEnv{alice, bob} {
		pgm := p.Registry.ProviderGroupManager
		pgm.RecomputeGroups()
		pg := pgm.GetGroupForZone(ZoneName(zd.ZoneName))
		if pg == nil {
			t.Fatalf("%s has no provider group for the zone", p.Identity)
		}
		group = pg.GroupHash
		// each agent's own row, as the engine writes it before its beats
		p.Registry.GossipStateTable.RefreshLocalStates(p.Registry, pgm)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("the peer's listener: %v", err)
	}
	bob.Registry.S.Set(AgentId(alice.Identity), NewAgent(AgentId(alice.Identity)))
	bob.Bridge.PeerRegistry.GetOrCreate(alice.Identity)
	bob.Bridge.StartIncomingMessageRouter(env.ctx)
	serveDNS(t, env.ctx, ln, bob)
	peer := peerFromAddress(bob.Identity, ln.Addr().String())
	peer.SetMechanismState("DNS", transport.PeerStateIntroducing, "said hello")
	if err := alice.Bridge.PeerRegistry.Add(peer); err != nil {
		t.Fatalf("the peer: %v", err)
	}
	agent := NewAgent(AgentId(bob.Identity))
	agent.DnsMethod = true
	if _, err := alice.Bridge.SendBeatWithFallback(env.ctx, agent, 1); err != nil {
		t.Fatalf("the beat: %v", err)
	}

	// bob has alice's row from the beat
	theirs, ours := bob.Registry.GossipStateTable, alice.Registry.GossipStateTable
	var d time.Duration
	var known bool
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end) && !known; time.Sleep(5 * time.Millisecond) {
		d, known = theirs.AnnouncedPropagationDelay(alice.Identity)
	}
	if !known || d != 7*time.Minute {
		t.Fatalf("bob has alice's propagation delay as %s (known=%v), want 7m0s", d, known)
	}
	theirs.mu.RLock()
	row := gossipMatrixRow(alice.Identity, theirs.States[group][alice.Identity])
	theirs.mu.RUnlock()
	if row["propagation_delay"] != uint32(420) {
		t.Errorf("the gossip API shows alice's row as %v, want propagation_delay 420", row)
	}
	// alice has bob's row from the beat's answer, and it announces none
	ours.mu.RLock()
	heard := ours.States[group][bob.Identity]
	ours.mu.RUnlock()
	if heard == nil {
		t.Fatal("alice did not get bob's row with the answer to her beat")
	}
	if d, known := ours.AnnouncedPropagationDelay(bob.Identity); known {
		t.Errorf("bob announces no propagation delay, and alice has %s", d)
	}
	if row := gossipMatrixRow(bob.Identity, heard); row["propagation_delay"] != nil {
		t.Errorf("the gossip API shows a propagation delay bob did not announce: %v", row)
	}
	// a row that is older than the one held does not take its place
	theirs.MergeGossip(&GossipMessage{GroupHash: group, Members: map[string]*MemberState{
		alice.Identity: {Identity: alice.Identity, Timestamp: time.Now().Add(-time.Hour), PropagationDelay: 1}}})
	if d, _ := theirs.AnnouncedPropagationDelay(alice.Identity); d != 7*time.Minute {
		t.Errorf("an older row replaced alice's propagation delay: %s", d)
	}
}

// The agent's own value is its dnssec.kasp.propagation-delay, and tdns's
// default when that is not set. An auditor serves nothing and announces
// none.
func TestTheAgentAnnouncesItsConfiguredPropagationDelay(t *testing.T) {
	for _, c := range []struct {
		role, setting string
		init          func(*Config, *MultiProviderConf) error
		want          time.Duration
	}{
		{"agent", "7m", (*Config).initMPAgent, 7 * time.Minute},
		{"agent", "", (*Config).initMPAgent, (&tdns.Config{}).KaspPropagationDelay()},
		{"auditor", "7m", (*Config).initMPAuditor, 0},
	} {
		conf := &Config{Config: &tdns.Config{}}
		conf.Config.Internal.StopCh = make(chan struct{})
		conf.Config.Dnssec.Kasp.PropagationDelay = c.setting
		mp := &MultiProviderConf{Role: c.role, Identity: c.role + ".delay.example."}
		conf.SetMpConfig(mp)
		err := c.init(conf, mp)
		close(conf.Config.Internal.StopCh)
		if err != nil {
			t.Fatalf("%s: init: %v", c.role, err)
		}
		gst := conf.InternalMp.AgentRegistry.GossipStateTable
		if got := gst.PropagationDelay(); got != c.want {
			t.Errorf("%s with propagation-delay %q: its own value is %s, want %s", c.role, c.setting, got, c.want)
		}
		// and it is in the agent's own row of a group, in whole seconds
		gst.UpdateLocalState("0123456789abcdef", nil, nil, 30)
		gst.mu.RLock()
		got := gst.States["0123456789abcdef"][gst.LocalID].PropagationDelay
		gst.mu.RUnlock()
		if got != uint32(c.want/time.Second) {
			t.Errorf("%s with propagation-delay %q announces %d s, want %d", c.role, c.setting, got, c.want/time.Second)
		}
	}
}

// The zone's wait is the largest propagation delay among the agent's own
// and those of the providers that serve the zone. A provider that only
// signs, an auditor and a member with no role do not count, however large
// their values; a serving provider whose value is not known is left out.
func TestTheWaitIsTheLargestPropagationDelayAmongTheServingProviders(t *testing.T) {
	const us = "agent.us.example."
	mpzd := signerTestZone(t, "wait.notify.example.", newMPTestKeyDB(t))
	z := mpzd.ZoneName
	apex, err := mpzd.OwnerForAnalysis(z)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: z, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600}
	}
	var h3s []dns.RR
	for _, label := range []string{"us", "p2", "p3", "p4", "aud", "idle"} {
		h3s = append(h3s, &dns.PrivateRR{Hdr: hdr(core.TypeHSYNC3), Data: &core.HSYNC3{State: 1, Label: label, Identity: "agent." + label + ".example.", Upstream: "."}})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: h3s})
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNCPARAM), Data: &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{
		&core.HSYNCPARAMServers{Servers: []string{"us", "p2", "p4"}},
		&core.HSYNCPARAMSigners{Signers: []string{"us", "p3"}},
		&core.HSYNCPARAMAuditors{Auditors: []string{"aud"}},
	}}}}})
	mpzd.Data.Set(z, *apex)
	mpzd.InstallInitialSnapshot()
	mpzd.Ready = true

	gst := NewGossipStateTable(us)
	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.AgentRegistry = &AgentRegistry{GossipStateTable: gst}
	// what each member's beats have brought: p4 serves, and announces none
	const group = "0123456789abcdef"
	announce := func(label string, seconds uint32) {
		id := "agent." + label + ".example."
		gst.MergeGossip(&GossipMessage{GroupHash: group, Members: map[string]*MemberState{
			id: {Identity: id, Timestamp: time.Now(), PropagationDelay: seconds}}})
	}
	announce("p2", 120)
	announce("p3", 900)
	announce("p4", 0)
	announce("aud", 3000)
	announce("idle", 6000)

	gst.SetPropagationDelay(time.Minute)
	if wait, of := conf.delegationNotifyWait(z); wait != 2*time.Minute || of != "agent.p2.example." {
		t.Errorf("the wait is %s, by %s; want p2's two minutes", wait, of)
	}
	gst.SetPropagationDelay(5 * time.Minute)
	if wait, of := conf.delegationNotifyWait(z); wait != 5*time.Minute || of != us {
		t.Errorf("the wait is %s, by %s; want this agent's own five minutes", wait, of)
	}
	// a provider's newer word counts, also when it comes in another group's gossip
	gst.MergeGossip(&GossipMessage{GroupHash: "fedcba9876543210", Members: map[string]*MemberState{
		"agent.p2.example.": {Identity: "agent.p2.example.", Timestamp: time.Now().Add(time.Second), PropagationDelay: 600}}})
	if wait, of := conf.delegationNotifyWait(z); wait != 10*time.Minute || of != "agent.p2.example." {
		t.Errorf("the wait is %s, by %s; want p2's ten minutes", wait, of)
	}
	// nobody says anything: no wait
	gst.SetPropagationDelay(0)
	announce("p2", 0)
	gst.MergeGossip(&GossipMessage{GroupHash: "fedcba9876543210", Members: map[string]*MemberState{
		"agent.p2.example.": {Identity: "agent.p2.example.", Timestamp: time.Now().Add(2 * time.Second)}}})
	if wait, _ := conf.delegationNotifyWait(z); wait != 0 {
		t.Errorf("the wait is %s with no propagation delay known, want none", wait)
	}
	// an agent with no gossip table, or a zone that is not here: no wait
	if wait, _ := (&Config{Config: &tdns.Config{}}).delegationNotifyWait(z); wait != 0 {
		t.Errorf("the wait is %s with no gossip table", wait)
	}
	gst.SetPropagationDelay(time.Minute)
	if wait, of := conf.delegationNotifyWait("absent.notify.example."); wait != time.Minute || of != us {
		t.Errorf("the wait for a zone that is not here is %s, by %s; want this agent's own", wait, of)
	}
}

// The wait before a NOTIFY has a ceiling, ten minutes unless the agent's
// configuration says otherwise: a provider that announces an hour does not
// hold the leader's NOTIFY for an hour. Zero switches the hold off. A number
// with no unit is read as nanoseconds and refused.
func TestTheWaitBeforeANotifyHasACeiling(t *testing.T) {
	gst := NewGossipStateTable("agent.us.example.")
	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.AgentRegistry = &AgentRegistry{GossipStateTable: gst}
	t.Cleanup(func() { viper.Set(notifyWaitMaxKey, nil) })
	const zone = "ceiling.notify.example." // not loaded: the wait is this agent's own value

	gst.SetPropagationDelay(time.Hour) // tdns's default for the setting
	if wait, _ := conf.delegationNotifyWait(zone); wait != 10*time.Minute {
		t.Errorf("with an hour announced and no ceiling configured the wait is %s, want the default ceiling of 10m", wait)
	}
	gst.SetPropagationDelay(5 * time.Minute)
	if wait, _ := conf.delegationNotifyWait(zone); wait != 5*time.Minute {
		t.Errorf("a value below the ceiling: the wait is %s, want the 5m announced", wait)
	}

	gst.SetPropagationDelay(time.Hour)
	for _, tc := range []struct {
		set  any
		want time.Duration
		why  string
	}{
		{"25m", 25 * time.Minute, "a configured ceiling"},
		{"2h", time.Hour, "a ceiling above what is announced changes nothing"},
		{"0", 0, "zero: no NOTIFY is held"},
		{600, 10 * time.Minute, "a number with no unit is refused, the default is used"},
		{"-5m", 10 * time.Minute, "a negative value is refused, the default is used"},
	} {
		viper.Set(notifyWaitMaxKey, tc.set)
		if wait, _ := conf.delegationNotifyWait(zone); wait != tc.want {
			t.Errorf("%s (%v): the wait is %s, want %s", tc.why, tc.set, wait, tc.want)
		}
	}
}
