/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Asking by itself (the membership design, 5.1 to 5.8): the catch-up
 * tracker. An agent asks each voting member of a zone for the zone's state
 * when it starts, when it joins the zone or gets its role there, when a
 * peer gets its role, starts or comes back after a long outage, and when
 * its operator asks. It keeps one request per zone and peer, asks again
 * until the answer is complete, and says when the zone is caught up.
 */

package tdnsmp

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

var lgCatchUp = tdns.Logger("catchup")

// The catch-up timers (design 5.7 and 5.8). Variables, so that a test can
// shorten them.
var (
	// catchUpAnswerWait: how long a request that was acknowledged waits for
	// its answer.
	catchUpAnswerWait = 30 * time.Second
	// catchUpRetryDelays, then catchUpRetryEvery: when a failed request is
	// asked again.
	catchUpRetryDelays = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, 60 * time.Second}
	catchUpRetryEvery  = 5 * time.Minute
	// catchUpRecent: a complete answer younger than this holds a new
	// request back (not the operator's).
	catchUpRecent = time.Minute
	// catchUpLogEvery: after a request's first failure, one line per this.
	catchUpLogEvery = time.Hour
)

// catchUpInFlight: the requests to one peer that wait for their answer at
// once (design 5.8).
const catchUpInFlight = 8

// The default of multi-provider.syncengine.intervals.catchup_outage: a peer
// that comes back after a longer gap between two successful beats is asked
// again.
const catchUpOutageDefault = 3600 * time.Second

// The reasons a request is made for.
const (
	catchUpStart     = "start"      // this agent started
	catchUpJoin      = "join"       // this agent joined the zone
	catchUpRole      = "role"       // this agent got its role in the zone
	catchUpPeerRole  = "peer-role"  // the peer got its role in the zone
	catchUpPeerStart = "peer-start" // the peer started, and asked this agent
	catchUpOutage    = "outage"     // the peer is back after a long outage
	catchUpManual    = "manual"     // the operator asked
)

// The states of an entry. Every state but idle is outstanding.
const (
	catchUpIdle   = "idle"
	catchUpNoted  = "noted"  // named, not sent: the peer is not OPERATIONAL
	catchUpDue    = "due"    // named, for the peer's sender to send
	catchUpSent   = "sent"   // sent, waiting for its acknowledgement and its answer
	catchUpRetry  = "retry"  // failed, asked again at its time
	catchUpPaused = "paused" // its retry found the peer not OPERATIONAL
)

// catchUpPeer is what the tracker holds for one zone and peer.
type catchUpPeer struct {
	State     string
	Request   string // the outstanding request's name
	Reason    string
	Asked     time.Time // when the request went out
	Answered  time.Time // when the last answer to a request of this entry came
	Complete  bool
	Why       string // a not complete answer's reason
	LastError string

	// startRequest, on a peer-start: the name of the peer's start request
	// it asks back for. The same start request delivered again is no new
	// start.
	startRequest string

	attempt  int       // the failures since the request was made
	acked    bool      // the request's send was acknowledged
	deadline time.Time // sent: the end of the wait for the answer; retry: when it is asked again
	loggedAt time.Time // the last failure line
}

func (e *catchUpPeer) outstanding() bool { return e.State != catchUpIdle }

// askResult is what Ask did.
type askResult int

const (
	askRecorded    askResult = iota // the request is recorded, and goes out
	askNoted                        // the peer is not OPERATIONAL: it goes out when it is
	askOutstanding                  // a request to the peer for the zone is outstanding
	askRecent                       // a complete answer is less than a minute old
)

func (r askResult) String() string {
	switch r {
	case askRecorded:
		return "the request is recorded"
	case askNoted:
		return "the request is noted: the peer is not operational, and it is sent when the peer is"
	case askOutstanding:
		return "no request is made: a request to the peer for the zone is outstanding"
	case askRecent:
		return "no request is made: the peer answered less than a minute ago"
	}
	return "unknown"
}

// catchUpTracker is the agent's catch-up tracker, one per process. The
// auditor has none: it holds none of the zones' data, and asks for nothing.
// Every hook does nothing where there is no tracker.
type catchUpTracker struct {
	mu    sync.Mutex
	peers map[ZoneName]map[AgentId]*catchUpPeer
	seen  map[AgentId]time.Time // the last successful beat to each peer

	self       AgentId
	startZones map[ZoneName]bool // the multi-provider zones the agent started with
	outage     time.Duration
	notAPeer   func(AgentId) bool // the agent's own combiner and signer
	// operational and send are the transport's; a test stands in for them.
	operational func(AgentId) bool
	send        func(ctx context.Context, zone ZoneName, peer AgentId, cu *CatchUp) error

	// Set when the data engine runs its main loop: nothing is sent before.
	ctx     context.Context
	zdr     *ZoneDataRepo
	senders map[AgentId]*catchUpSender
	wg      sync.WaitGroup
	caught  map[ZoneName]bool // the zones whose catch-up was logged
}

// newCatchUpTracker is the agent's tracker. startZones are the
// multi-provider zones the agent starts with (MPZoneNames as initMPAgent
// finds it): the first load of any other zone asks with join.
func newCatchUpTracker(self AgentId, startZones []string, outage time.Duration) *catchUpTracker {
	t := &catchUpTracker{
		peers:       map[ZoneName]map[AgentId]*catchUpPeer{},
		seen:        map[AgentId]time.Time{},
		self:        AgentId(dns.Fqdn(string(self))),
		startZones:  map[ZoneName]bool{},
		outage:      outage,
		notAPeer:    func(AgentId) bool { return false },
		operational: func(AgentId) bool { return false },
		send: func(context.Context, ZoneName, AgentId, *CatchUp) error {
			return fmt.Errorf("no transport")
		},
		senders: map[AgentId]*catchUpSender{},
		caught:  map[ZoneName]bool{},
	}
	for _, z := range startZones {
		t.startZones[ZoneName(dns.Fqdn(z))] = true
	}
	return t
}

// wire gives the tracker the agent's transport: who is OPERATIONAL, how a
// request is sent, and which identities are the agent's own combiner and
// signer.
func (t *catchUpTracker) wire(tm *MPTransportBridge, ar *AgentRegistry) {
	t.operational = ar.isAgentOperational
	t.notAPeer = func(id AgentId) bool {
		return isAmong([]string{string(tm.combinerID), string(tm.signerID)}, id)
	}
	t.send = func(ctx context.Context, zone ZoneName, peer AgentId, cu *CatchUp) error {
		agent, ok := ar.S.Get(peer)
		if !ok {
			return fmt.Errorf("agent %q is not known", peer)
		}
		_, err := ar.sendRfiToAgentCtx(ctx, agent, &AgentMsgPost{
			MessageType:  AgentMsgRfi,
			OriginatorID: AgentId(ar.LocalAgent.Identity),
			YourIdentity: peer,
			Zone:         zone,
			RfiType:      "SYNC",
			CatchUp:      cu,
		})
		return err
	}
}

// run starts the sending: the data engine has done its start-up hydration
// and runs its main loop, so answers to the requests, and requests back,
// no longer wait on it. The senders run on ctx.
func (t *catchUpTracker) run(ctx context.Context, zdr *ZoneDataRepo) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ctx, t.zdr = ctx, zdr
	for _, byPeer := range t.peers {
		for peer, e := range byPeer {
			if e.State == catchUpDue {
				t.kickLocked(peer)
			}
		}
	}
}

// wait waits for the senders, once the context they run on has ended.
func (t *catchUpTracker) wait() {
	if t != nil {
		t.wg.Wait()
	}
}

// entryLocked is the entry for the zone and peer, made when there is none.
func (t *catchUpTracker) entryLocked(zone ZoneName, peer AgentId) *catchUpPeer {
	if t.peers[zone] == nil {
		t.peers[zone] = map[AgentId]*catchUpPeer{}
	}
	e := t.peers[zone][peer]
	if e == nil {
		e = &catchUpPeer{State: catchUpIdle}
		t.peers[zone][peer] = e
	}
	return e
}

// Ask records a request for the zone's state to peer, with a new name,
// unless one to that peer for that zone is outstanding, or the peer's
// complete answer is less than a minute old. The minute holds neither
// manual (decision 38) nor peer-start: a peer that restarted within the
// minute of its answer has lost its queue since, and asking it back is the
// only way to its last change (design 5.1). Nor does an outstanding
// request hold peer-start: it is made anew, under a new name, so that an
// answer the peer's earlier process built, still on its way, names a
// request that is no longer outstanding and counts for nothing. That holds
// for an outstanding peer-start too, once it has gone out: the peer may
// have started again since, and an answer from the process before is no
// answer for what the peer lost then. A peer-start not yet sent goes out to
// the process that runs now, and stands; so does one asked back for the
// same start request, delivered again. A start request asked again by the
// same process, after a failure, has a new name and is made anew as well:
// its retries are 5 s apart at the least, so they do not starve the answer.
// A request clears Complete. To a peer that is not OPERATIONAL it is noted,
// and goes out at PeerOperational. Ask only records: the peer's sender
// sends.
func (t *catchUpTracker) Ask(zone ZoneName, peer AgentId, reason string) askResult {
	return t.ask(zone, peer, reason, "")
}

// ask is Ask, with the name of the peer's start request that a peer-start
// asks back for (Requested).
func (t *catchUpTracker) ask(zone ZoneName, peer AgentId, reason, startRequest string) askResult {
	if t == nil {
		return askOutstanding
	}
	zone, peer = ZoneName(dns.Fqdn(string(zone))), AgentId(dns.Fqdn(string(peer)))
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entryLocked(zone, peer)
	if e.outstanding() {
		switch {
		case reason != catchUpPeerStart:
			return askOutstanding
		case e.Reason == catchUpPeerStart && (e.State != catchUpSent || (startRequest != "" && e.startRequest == startRequest)):
			return askOutstanding
		}
		lgCatchUp.Info("a peer started while a request to it was outstanding; the request is made anew", "zone", zone, "peer", peer,
			"replaced", e.Request, "reason", e.Reason)
	}
	if reason != catchUpManual && reason != catchUpPeerStart && e.Complete && time.Since(e.Answered) < catchUpRecent {
		return askRecent
	}
	*e = catchUpPeer{Request: newRfiNonce(), Reason: reason, Answered: e.Answered, Why: e.Why, startRequest: startRequest}
	delete(t.caught, zone)
	if !t.operational(peer) {
		e.State = catchUpNoted
		return askNoted
	}
	e.State = catchUpDue
	t.kickLocked(peer)
	return askRecorded
}

// AskZone asks every voting member of the zone other than this agent, in a
// zone in which this agent votes. An agent with no role in the zone asks
// nothing: its peers would refuse it until the switch (issue 158), and it
// asks with role when the role comes. The auditor holds nothing and asks
// nothing (decision 36). It returns what each Ask did, nil where nothing is
// asked.
//
// Only a zone that is multi-provider here is asked about: one to which the
// load gave provider data (populateMPdata). A zone with HSYNC3 records and
// no HSYNCPARAM has none, and no agent can answer for it complete: asking
// would repeat every five minutes for ever. Whether such a zone is
// multi-provider is the transitions design's question.
func (t *catchUpTracker) AskZone(zone ZoneName, reason string) map[AgentId]askResult {
	if t == nil || !isVotingMember(zone, string(t.self)) {
		return nil
	}
	if zd, ok := Zones.Get(string(zone)); !ok || !zd.hasProviderData() {
		return nil
	}
	out := map[AgentId]askResult{}
	for _, peer := range votingPeers(zone, t.self) {
		out[peer] = t.Ask(zone, peer, reason)
	}
	return out
}

// PeerOperational notes a successful beat to peer. It first sends every
// request to it that waits for it. Then, the first time since this agent
// started, it asks the peer with start for every zone they share that has
// loaded, in which both vote; after a gap above the outage time between two
// successful beats, the same with outage. A beat to the agent's own
// combiner or signer is no peer's.
func (t *catchUpTracker) PeerOperational(peer AgentId) {
	if t == nil || t.notAPeer(peer) {
		return
	}
	peer = AgentId(dns.Fqdn(string(peer)))
	now := time.Now()
	t.mu.Lock()
	prev, beaten := t.seen[peer]
	t.seen[peer] = now
	for _, byPeer := range t.peers {
		e := byPeer[peer]
		if e == nil {
			continue
		}
		switch e.State {
		case catchUpNoted:
			e.State = catchUpDue
		case catchUpPaused:
			e.State, e.Request = catchUpDue, newRfiNonce()
		}
	}
	t.kickLocked(peer)
	t.mu.Unlock()

	reason := ""
	switch {
	case !beaten:
		reason = catchUpStart
	case now.Sub(prev) > t.outage:
		reason = catchUpOutage
	}
	if reason == "" {
		return
	}
	for _, zone := range t.sharedZones(peer) {
		t.Ask(zone, peer, reason)
	}
}

// sharedZones are the multi-provider zones that have loaded here, with the
// provider data AskZone asks for at a load, and in which both this agent
// and peer vote. A zone with HSYNC3 records and no HSYNCPARAM has no
// provider data, and is asked about neither at a load nor at a beat.
func (t *catchUpTracker) sharedZones(peer AgentId) []ZoneName {
	var out []ZoneName
	for _, name := range Zones.Keys() {
		zd, ok := Zones.Get(name)
		if !ok || !zd.Options[tdns.OptMultiProvider] || !zd.loadedForCatchUp() {
			continue
		}
		zone := ZoneName(zd.ZoneName)
		if isVotingMember(zone, string(t.self)) && isVotingMember(zone, string(peer)) {
			out = append(out, zone)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Answered takes an answer from peer that names the request outstanding to
// it for the zone. A complete answer ends the request; one that is not
// complete fails it, and it is asked again. An answer to another request,
// one that timed out among them, counts for nothing.
func (t *catchUpTracker) Answered(zone ZoneName, peer AgentId, cu *CatchUp) {
	if t == nil || cu == nil {
		return
	}
	zone, peer = ZoneName(dns.Fqdn(string(zone))), AgentId(dns.Fqdn(string(peer)))
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.peers[zone][peer]
	if e == nil || e.State != catchUpSent || e.Request != cu.Request {
		return
	}
	now := time.Now()
	e.Answered = now
	if !cu.IsComplete() {
		e.Why = cu.Why
		t.failLocked(zone, peer, e, "the answer is not complete: "+cu.Why, now)
		t.kickLocked(peer)
		return
	}
	e.State, e.Complete, e.Why, e.LastError, e.attempt = catchUpIdle, true, "", "", 0
	t.kickLocked(peer)
	t.noteCaughtUpLocked(zone)
}

// Requested is told of each answer this agent enqueued for a peer's
// request: a peer that started asks this agent, which asks it back, so that
// the peer's queue, lost at its start, is made good (decision 5). Only for
// reason start, and only when both vote in the zone.
func (t *catchUpTracker) Requested(zone ZoneName, from AgentId, cu *CatchUp) {
	if t == nil || cu == nil || cu.Reason != catchUpStart {
		return
	}
	if !isVotingMember(zone, string(from)) || !isVotingMember(zone, string(t.self)) {
		return
	}
	t.ask(zone, from, catchUpPeerStart, cu.Request)
}

// Forget drops everything kept for a peer that is removed, so that one
// named again later is asked as a new peer.
func (t *catchUpTracker) Forget(peer AgentId) {
	if t == nil {
		return
	}
	peer = AgentId(dns.Fqdn(string(peer)))
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.seen, peer)
	if s, ok := t.senders[peer]; ok {
		close(s.stop)
		delete(t.senders, peer)
	}
	for zone, byPeer := range t.peers {
		if _, ok := byPeer[peer]; ok {
			delete(byPeer, peer)
			t.noteCaughtUpLocked(zone)
		}
	}
}

// catchUpWait is whom a zone that is not caught up waits for.
type catchUpWait struct {
	OwnRead    bool   // this agent's own state is read
	OwnReadWhy string // why not
	Peers      []AgentId
}

func (w catchUpWait) String() string {
	var parts []string
	if !w.OwnRead {
		parts = append(parts, fmt.Sprintf("this agent's own state (%s)", w.OwnReadWhy))
	}
	for _, p := range w.Peers {
		parts = append(parts, string(p))
	}
	return strings.Join(parts, ", ")
}

// CaughtUp: the zone's own read is done (from its combiner, and for a
// provider in signers= from its signer: the inventory is in), and every
// voting member of the zone other than this agent, as the zone's records name them now, has
// answered complete, with no request outstanding to it (design 5.5). It
// also says whom it waits for.
func (t *catchUpTracker) CaughtUp(zone ZoneName) (bool, catchUpWait) {
	if t == nil {
		return true, catchUpWait{OwnRead: true}
	}
	zone = ZoneName(dns.Fqdn(string(zone)))
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.caughtUpLocked(zone)
}

func (t *catchUpTracker) caughtUpLocked(zone ZoneName) (bool, catchUpWait) {
	var w catchUpWait
	signsWithout := false
	if zd, ok := Zones.Get(string(zone)); ok {
		signsWithout = zd.signsWithoutInventory()
	}
	switch {
	case t.zdr == nil:
		w.OwnReadWhy = "the data engine has not started"
	case !t.zdr.OwnStateRead(zone):
		w.OwnReadWhy = t.zdr.ownStateWhy(zone)
	case signsWithout:
		// the signer's half of the own read: a provider in signers= has
		// its signer's inventory (design 5.5)
		w.OwnReadWhy = whyNoInventory
	default:
		w.OwnRead = true
	}
	for _, peer := range votingPeers(zone, t.self) {
		e := t.peers[zone][AgentId(dns.Fqdn(string(peer)))]
		if e == nil || !e.Complete || e.outstanding() {
			w.Peers = append(w.Peers, peer)
		}
	}
	return w.OwnRead && len(w.Peers) == 0, w
}

// noteCaughtUpLocked logs the zone's catch-up once, when it is caught up.
func (t *catchUpTracker) noteCaughtUpLocked(zone ZoneName) {
	if t.caught[zone] {
		return
	}
	if ok, _ := t.caughtUpLocked(zone); ok {
		t.caught[zone] = true
		lgCatchUp.Info("the zone is caught up", "zone", zone)
	}
}

// ownReadDone is told that the zone's own read is done: the zone may be
// caught up now.
func (t *catchUpTracker) ownReadDone(zone ZoneName) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.noteCaughtUpLocked(ZoneName(dns.Fqdn(string(zone))))
}

// prune drops the zone's entries that no longer apply: the zone is not held
// here, this agent no longer votes in it, or the peer no longer does.
func (t *catchUpTracker) prune(zone ZoneName) {
	if t == nil {
		return
	}
	zone = ZoneName(dns.Fqdn(string(zone)))
	t.mu.Lock()
	defer t.mu.Unlock()
	for peer := range t.peers[zone] {
		if !t.appliesLocked(zone, peer) {
			delete(t.peers[zone], peer)
		}
	}
	if len(t.peers[zone]) == 0 {
		delete(t.peers, zone)
	}
	t.noteCaughtUpLocked(zone)
}

// appliesLocked: an entry still applies. Whether the zone is held is asked
// of tdns: a zone taken out at a reload leaves tdns.Zones, and the wrapper
// Zones keeps of it, with its data, stays.
func (t *catchUpTracker) appliesLocked(zone ZoneName, peer AgentId) bool {
	if _, held := tdns.Zones.Get(string(zone)); !held {
		return false
	}
	return isVotingMember(zone, string(t.self)) && isVotingMember(zone, string(peer))
}

// afterRefresh asks what a refresh calls for (the reasons at a refresh):
// at the zone's first load, start for a zone the agent started with and
// join for one added since, and nothing else; at a later refresh, join when
// this agent's standing rose from none, role when it rose to voting, and
// peer-role for each other identity that became a voting member, in a zone
// in which this agent votes. Entries that no longer apply are dropped.
func (t *catchUpTracker) afterRefresh(zone ZoneName, a *ZoneRefreshAnalysis) {
	if t == nil || a == nil {
		return
	}
	zone = ZoneName(dns.Fqdn(string(zone)))
	if a.FirstLoad {
		reason := catchUpJoin
		if t.startZones[zone] {
			reason = catchUpStart
		}
		t.AskZone(zone, reason)
		return
	}
	t.prune(zone)
	switch {
	case a.StandingBefore == standingNone && a.StandingAfter != standingNone:
		t.AskZone(zone, catchUpJoin)
	case a.StandingAfter == standingVoting && a.StandingBefore != standingVoting:
		t.AskZone(zone, catchUpRole)
	}
	if !isVotingMember(zone, string(t.self)) {
		return
	}
	for _, peer := range a.NewVoters {
		if !isAmong([]string{string(t.self)}, peer) {
			t.Ask(zone, peer, catchUpPeerRole)
		}
	}
}

// catchUpSender is a peer's sender's wake-up, and its end when the peer is
// forgotten.
type catchUpSender struct {
	wake chan struct{}
	stop chan struct{}
}

// kickLocked wakes the peer's sender, and starts it when there is none.
// Nothing is sent before the data engine runs (run).
func (t *catchUpTracker) kickLocked(peer AgentId) {
	if t.ctx == nil {
		return
	}
	if s, ok := t.senders[peer]; ok {
		select {
		case s.wake <- struct{}{}:
		default:
		}
		return
	}
	s := &catchUpSender{wake: make(chan struct{}, 1), stop: make(chan struct{})}
	t.senders[peer] = s
	t.wg.Add(1)
	go t.sender(t.ctx, peer, s)
}

// sender sends the requests to one peer, one at a time, and keeps their
// timers: the wait for each answer, and each retry. A send ends at its
// acknowledgement, which can take the transport's 15 s, so no caller of
// Ask waits for it.
func (t *catchUpTracker) sender(ctx context.Context, peer AgentId, s *catchUpSender) {
	defer t.wg.Done()
	for {
		zone, cu, next := t.step(peer, time.Now())
		if cu != nil {
			err := t.send(ctx, zone, peer, cu)
			t.sent(zone, peer, cu.Request, err)
			continue
		}
		wait := time.Hour
		if !next.IsZero() {
			wait = max(time.Until(next), 0)
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-s.stop:
			timer.Stop()
			return
		case <-s.wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// step does what is due for peer: a request whose answer did not come in
// time fails; a retry whose time has come is named anew, or paused when the
// peer is not OPERATIONAL, or dropped when it no longer applies. Then it
// picks the next request to send, when fewer than eight wait for their
// answers, and says when it next has something to do.
func (t *catchUpTracker) step(peer AgentId, now time.Time) (ZoneName, *CatchUp, time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	operational := t.operational(peer)
	zones := make([]ZoneName, 0, len(t.peers))
	for zone := range t.peers {
		zones = append(zones, zone)
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i] < zones[j] })
	inFlight := 0
	for _, zone := range zones {
		e := t.peers[zone][peer]
		if e == nil {
			continue
		}
		switch {
		case e.State == catchUpSent && e.acked && !now.Before(e.deadline):
			t.failLocked(zone, peer, e, fmt.Sprintf("no answer within %s", catchUpAnswerWait), now)
		case e.State == catchUpRetry && !now.Before(e.deadline):
			switch {
			case !t.appliesLocked(zone, peer):
				delete(t.peers[zone], peer)
				continue
			case !operational:
				e.State = catchUpPaused
			default:
				e.State, e.Request, e.acked = catchUpDue, newRfiNonce(), false
			}
		case e.State == catchUpDue && !operational:
			e.State = catchUpNoted
		}
		if e.State == catchUpSent {
			inFlight++
		}
	}
	var next time.Time
	for _, zone := range zones {
		e := t.peers[zone][peer]
		if e == nil {
			continue
		}
		if e.State == catchUpDue && inFlight < catchUpInFlight {
			e.State, e.Asked, e.acked, e.deadline = catchUpSent, now, false, time.Time{}
			if e.attempt == 0 {
				lgCatchUp.Info("asking a peer for the zone's state", "zone", zone, "peer", peer, "reason", e.Reason, "request", e.Request)
			}
			return zone, &CatchUp{Request: e.Request, Reason: e.Reason}, time.Time{}
		}
		if (e.State == catchUpRetry || (e.State == catchUpSent && e.acked)) && (next.IsZero() || e.deadline.Before(next)) {
			next = e.deadline
		}
	}
	return "", nil, next
}

// sent takes the outcome of a send: an error fails the request; an
// acknowledgement starts the wait for its answer, unless the answer came
// first.
func (t *catchUpTracker) sent(zone ZoneName, peer AgentId, request string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.peers[zone][peer]
	if e == nil || e.State != catchUpSent || e.Request != request {
		return
	}
	now := time.Now()
	if err != nil {
		t.failLocked(zone, peer, e, err.Error(), now)
		return
	}
	e.acked, e.deadline = true, now.Add(catchUpAnswerWait)
}

// failLocked fails the entry's request: it is asked again after 5 s, 15 s,
// 30 s and 60 s, then every 5 minutes, with the same reason and a new name.
// The first failure is logged, then one line an hour.
func (t *catchUpTracker) failLocked(zone ZoneName, peer AgentId, e *catchUpPeer, cause string, now time.Time) {
	e.attempt++
	e.LastError = cause
	in := catchUpRetryEvery
	if e.attempt <= len(catchUpRetryDelays) {
		in = catchUpRetryDelays[e.attempt-1]
	}
	e.State, e.deadline, e.acked = catchUpRetry, now.Add(in), false
	if e.attempt == 1 || now.Sub(e.loggedAt) >= catchUpLogEvery {
		e.loggedAt = now
		lgCatchUp.Warn("a request for the zone's state failed, asking again", "zone", zone, "peer", peer,
			"reason", e.Reason, "cause", cause, "attempt", e.attempt, "in", in)
	}
}

// CatchUpStatus is the zone's catch-up, for agent parentsync status.
type CatchUpStatus struct {
	NotVoting  bool                `json:"not_voting,omitempty"` // this agent does not vote in the zone, and asks nothing
	CaughtUp   bool                `json:"caught_up"`
	WaitingFor string              `json:"waiting_for,omitempty"`
	Peers      []CatchUpPeerStatus `json:"peers,omitempty"`
}

// CatchUpPeerStatus is one voting member's row.
type CatchUpPeerStatus struct {
	Identity AgentId   `json:"identity"`
	Answer   string    `json:"answer"` // complete, not complete or none
	Asked    time.Time `json:"asked,omitempty"`
	Answered time.Time `json:"answered,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Note     string    `json:"note,omitempty"` // why it is not complete, or why the request failed
}

// Status is the zone's catch-up: whether it is caught up, whom it waits
// for, and a row per voting member other than this agent.
func (t *catchUpTracker) Status(zone ZoneName) *CatchUpStatus {
	if t == nil {
		return nil
	}
	zone = ZoneName(dns.Fqdn(string(zone)))
	if !isVotingMember(zone, string(t.self)) {
		return &CatchUpStatus{NotVoting: true}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	ok, w := t.caughtUpLocked(zone)
	s := &CatchUpStatus{CaughtUp: ok}
	if !ok {
		s.WaitingFor = w.String()
	}
	for _, peer := range votingPeers(zone, t.self) {
		row := CatchUpPeerStatus{Identity: peer, Answer: "none"}
		if e := t.peers[zone][AgentId(dns.Fqdn(string(peer)))]; e != nil {
			row.Asked, row.Answered, row.Reason = e.Asked, e.Answered, e.Reason
			switch {
			case e.Complete:
				row.Answer = "complete"
			case !e.Answered.IsZero() && e.Why != "":
				row.Answer, row.Note = "not complete", e.Why
			}
			switch {
			case e.State == catchUpNoted || e.State == catchUpPaused:
				row.Note = "the peer is not operational"
			case row.Note == "" && e.LastError != "":
				row.Note = catchUpCause(e.LastError)
			}
		}
		s.Peers = append(s.Peers, row)
	}
	return s
}

// catchUpCause is a failure's cause, shortened for the status.
func catchUpCause(err string) string {
	switch {
	case strings.Contains(err, "REJECTED") || strings.Contains(strings.ToLower(err), "refused"):
		return "refused"
	case strings.HasPrefix(err, "no answer within"):
		return "no answer"
	}
	return err
}
