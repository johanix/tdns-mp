/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * tdns-mp #175: a delegation sync that goes to the parent as a NOTIFY is
 * not done when the NOTIFY has been sent. The leader looks at the parent
 * again, sends again while the parent still differs, and tells its peers
 * when the parent is in sync.
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

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
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
	peer    *peerEnv
	notifyq chan tdns.NotifyRequest
	log     *lockedBuffer
	ctx     context.Context
	ksk     KeyInventoryItem // the zone's KSK, as its signer reports it
	ds      dns.RR           // the DS of that key
	oldNS   string           // a nameserver the zone no longer lists
}

// newNotifyRig starts the rig for a zone whose parent advertises the given
// DSYNC scheme ("NOTIFY" or "UPDATE"). The parent starts in sync with the
// zone. delays replaces delegationSyncNotifyDelays.
func newNotifyRig(t *testing.T, zone, scheme string, delays ...time.Duration) *notifyRig {
	t.Helper()
	savedDelays, savedLog := delegationSyncNotifyDelays, lgEngine
	logsink := &lockedBuffer{}
	delegationSyncNotifyDelays = delays
	lgEngine = slog.New(slog.NewTextHandler(logsink, nil))
	// registered first, so run last: after the syncher has stopped
	t.Cleanup(func() { delegationSyncNotifyDelays, lgEngine = savedDelays, savedLog })
	installParentSync(t, fmt.Sprintf(parentSyncConfig, "ED25519"))

	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	us, them := env.Alice, env.Bob
	r := &notifyRig{leaderSyncRig: newLeaderSyncRigAs(t, zone, AgentId(us.Identity)), peer: them,
		notifyq: make(chan tdns.NotifyRequest, 64), log: logsink, oldNS: "gone.provider.example."}
	r.leader(AgentId(us.Identity))
	r.conf.InternalMp.MPTransport = us.Bridge
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
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNCPARAM),
		Data: &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{&core.HSYNCPARAMServers{Servers: labels}}}}}})
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

	// the syncher, and the DS engine it asks for the CDS before a NOTIFY(CDS)
	ctx, cancel := context.WithCancel(context.Background())
	r.ctx = ctx
	ensureDSEngineQueue(zd.KeyDB)
	var engines sync.WaitGroup
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
		cancel()
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
	r.e.handleKeystateInventory(r.ctx, r.lem.localID, &KeystateInventoryMsg{SenderID: "signer.alice.example.", Zone: z,
		Inventory: []KeyInventoryItem{r.ksk}, Owned: true}, r.sdq, nil)
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
// peers are told at once, and nothing looks at the parent again.
func TestAnUpdateIsDoneWhenTheParentHasAnswered(t *testing.T) {
	r := newNotifyRig(t, "update.notify.example.", "UPDATE", repeat(30*time.Millisecond, 400)...)
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
	if l := r.log.String(); strings.Contains(l, logCheckAgain) || strings.Contains(l, "which is checked again") {
		t.Errorf("a sync sent as an UPDATE was checked again:\n%s", l)
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
	r.e.handleKeystateInventory(r.ctx, r.lem.localID, &KeystateInventoryMsg{SenderID: "signer.alice.example.", Zone: z,
		Inventory: []KeyInventoryItem{r.ksk}, Owned: true}, r.sdq, nil)
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
	r.e.handleKeystateInventory(r.ctx, r.lem.localID, &KeystateInventoryMsg{SenderID: "signer.alice.example.", Zone: z,
		Inventory: []KeyInventoryItem{r.ksk, next}, Owned: true}, r.sdq, nil)
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
	ctx := context.Background()
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

	// a check's own sync fails: the failure asks again by its own delays,
	// and the NOTIFY is not forgotten
	r.conf.delegationSyncNotifiedWith(ctx, z, "CDS", short)
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
	r.conf.delegationSyncNotifiedWith(ctx, z, "CDS", short)
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
	r.conf.delegationSyncNotifiedWith(ctx, z, "CSYNC", short)
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
	r.conf.delegationSyncNotifiedWith(ctx, z, "CSYNC", long)
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
	r.conf.delegationSyncNotifiedWith(ctx, z, "CSYNC", long)
	r.conf.delegationSyncNotifiedWith(ctx, z, "CDS", short)
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
	r.conf.delegationSyncNotifiedWith(ctx, z, "CSYNC", long)
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
		r.conf.delegationSyncNotifiedWith(ctx, z, "CDS", long)  // the chain's own
		r.conf.delegationSyncNotifiedWith(ctx, z, "CDS", short) // something else's, while the check waits
		if ch, _ := chain(); ch.rechecks != check {
			t.Errorf("check %d: the chain counts %d", check, ch.rechecks)
		}
		if n := r.waitRequests(t, 1, 2*time.Second); n != 1 {
			t.Fatalf("check %d: %d sync requests, want 1", check, n)
		}
	}
	r.conf.delegationSyncNotifiedWith(ctx, z, "CDS", short)
	if _, n := chain(); n != 0 {
		t.Errorf("past the bound %d chains are left", n)
	}
	time.Sleep(400 * time.Millisecond)
	if n := r.requests(t); n != 0 {
		t.Errorf("past the bound %d syncs were asked for", n)
	}
}

// The words the scheme is read from are tdns's. The tests above hold the
// two NOTIFY types to what the pinned tdns says, through its own sync; here
// is what must not be taken for a NOTIFY.
func TestOnlyANotifyThatWasSentIsChecked(t *testing.T) {
	for msg, want := range map[string]string{
		"SyncZoneDelegationViaNotify: Sent NOTIFY(CSYNC, CDS) for zone child.example. to NotifierEngine":                                     "CSYNC, CDS",
		"SyncZoneDelegationViaNotify: Sent NOTIFY(CDS) for zone child.example. to NotifierEngine (after UPDATE failed: parent said REFUSED)": "CDS",
		"SyncZoneDelegationViaNotify: nothing to notify for zone child.example.":                                                             "",
		"SendUpdate(example.) returned rcode NOERROR":                                                                                        "",
		"SendUpdate(example.) returned rcode NOERROR (after NOTIFY failed: zone child.example.: no CDS for a NOTIFY(CDS) to point at)":       "",
		"": "",
	} {
		if got := notifiesSent(msg); got != want {
			t.Errorf("notifiesSent(%q) = %q, want %q", msg, got, want)
		}
	}
	// not a multi-provider zone the leader syncs: the agent's own identity
	// zone has its own loop, and no election to ask through
	r := newLeaderSyncRig(t, "plain.notify.example.")
	r.leader("agent.us.example.")
	sent := "SyncZoneDelegationViaNotify: Sent NOTIFY(CDS) for zone " + r.mpzd.ZoneName + " to NotifierEngine"
	ds := tdns.DelegationSyncRequest{ZoneName: r.mpzd.ZoneName, ZoneData: r.mpzd.ZoneData}
	r.mpzd.Options[tdns.OptMultiProvider] = false
	if r.conf.delegationSyncNotified(context.Background(), ds, sent) {
		t.Error("a NOTIFY for a zone that is not multi-provider was put on the leader's chain")
	}
	r.mpzd.Options[tdns.OptMultiProvider] = true
	if r.conf.delegationSyncNotified(context.Background(), ds, "SendUpdate(example.) returned rcode NOERROR") {
		t.Error("an UPDATE was put on the leader's chain as a NOTIFY")
	}
	if n := len(r.conf.InternalMp.delegationSyncChains.zones); n != 0 {
		t.Errorf("%d chains started", n)
	}
}
