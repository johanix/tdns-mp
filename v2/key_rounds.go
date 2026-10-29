/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"fmt"
	"sort"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// A voting member asks for the zone's SIG(0) key it does not hold (step 7b,
// settle point 2).
//
// The tracker keeps, per zone, the round of requests for the key that is
// out, and what each agent asked answered (keyWanted). The rounds run on the
// tracker's own goroutine, with step 4's pacing: after 5 s, 15 s, 30 s and
// 60 s, then every 5 minutes; a zone that becomes caught up gets its next
// round at once. A round asks every agent of zoneKeyPeers again, also one
// that said "no key" before: it may have got the key since.
//
// An answer counts only when its stamp carries the active serial this agent
// had when the round went out, and the round starts over when this agent's
// active serial changes (plan S14, design rule 6): a "no key here" told
// under other instructions says nothing of the voting members under these.
//
// A key request is an entry of its own kind on the per-peer sender: CONFIG
// sig0key, with the round's nonce and distribution ID, sent one at a time,
// never renamed or retried (the next round asks again), and outside the
// catch-up's appliesLocked and prune (a holder with no role is asked too).
// Each request has a waiter: its answer is due 15 s after the sender's
// acknowledgement; a send that failed reaches it as "not taken". When every
// agent asked has answered, the round's decision runs on the last waiter's
// goroutine, under the zone's key-setup lock (inKeySetup), never under the
// tracker's (lock order: inKeySetup, then the tracker's).

// The key rounds' timers. Variables, so that a test can shorten them.
var (
	// keyAnswerWait: how long a key request that was acknowledged waits
	// for its answer.
	keyAnswerWait = 15 * time.Second
	// keyUnsentWait: how long a key request may wait for its sender; one
	// not sent by then counts as silence and is taken off the queue.
	keyUnsentWait = 30 * time.Second
	// keyRoundDelays, then keyRoundEvery: when a round that did not end
	// with the key held is asked again.
	keyRoundDelays = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, 60 * time.Second}
	keyRoundEvery  = 5 * time.Minute
	// keyRoundTick: how often the tracker looks for a round that is due.
	keyRoundTick = time.Second
)

// keyInFlight: the key requests to one peer that wait for their answer at
// once. Key requests do not share the catch-up's slots: one round has one
// request per zone and peer.
const keyInFlight = 8

// What an agent asked for the key answered.
const (
	keyGot         = "key"          // a key, to import
	keyNotImported = "not imported" // a key, which the import refused
	keyNone        = "no key"       // "no sig0 key for zone": it holds none
	keyRefused     = "refused"      // it refused to hand the key over (it may hold it)
	keySilent      = "silence"      // no answer in time, or not OPERATIONAL
	keyNotTaken    = "not taken"    // the request was not delivered
	keyNoData      = "no data"      // an answer with no data: not "no key"
	keySeveral     = "several KEYs" // its apex carries several KEYs: not "no key"
	keyOtherSerial = "other serial" // a key or "no key" told under another active serial: counts for nothing (S14)
)

// sig0StatusSeveral is the holder's status when the apex of its copy of the
// zone carries several KEYs.
const sig0StatusSeveral = "several KEYs at the apex"

type keyReply struct {
	outcome string
	detail  string
	data    map[string]string
	instr   *MsgStamp // the answerer's stamp
}

// keyRound is a zone's entry in keyWanted.
type keyRound struct {
	gen     uint64 // the round's generation: an answer to an earlier one counts for nothing
	rounds  int    // rounds asked so far
	next    time.Time
	out     bool // a round is out
	decided bool // the round's decision has started
	asked   []AgentId
	answers map[AgentId]keyReply
	// serial is this agent's active serial when the round went out (known
	// false: it knew none); only an answer stamped with it counts
	serial SerialDigest
	known  bool
}

// keyReq is one key request of a round.
type keyReq struct {
	zone   ZoneName
	peer   AgentId
	gen    uint64
	nonce  string
	distID string
	sent   bool
	result chan error // the send's result: nil when acknowledged
	stop   chan struct{}
	answer <-chan *ConfigResponseMsg
	// cancelWait ends the registration with the answer's waiters, and
	// closeAsk this request's window for the key's hand-over (keyAsks):
	// both idempotent.
	cancelWait func()
	closeAsk   func()
}

// keyHooks are the agent's parts of the rounds; a test stands in for them.
type keyHooks struct {
	// wants: this agent votes in the zone, the zone is here and uses a
	// key, and this agent does not hold the zone's key. Asks the resolver
	// and reads the keystore: never called under the tracker's lock.
	wants func(ctx context.Context, zone ZoneName) bool
	// peers: the agents asked (zoneKeyPeers).
	peers func(zone ZoneName) []AgentId
	// active: this agent's active serial for the zone, and whether it
	// knows one (S14). Reads the store: never called under the tracker's
	// lock.
	active func(zone ZoneName) (SerialDigest, bool)
	// prepare registers the request's answer and its window, before the
	// request is queued.
	prepare func(kr *keyReq)
	// send sends the request, and returns when the peer acknowledged it.
	send func(ctx context.Context, kr *keyReq) error
	// decide runs when a round has every answer: true when the zone's key
	// is held now, or the round is over for good.
	decide func(ctx context.Context, zone ZoneName, answers map[AgentId]keyReply) bool
}

// keyCheck notes that the zone's key is to be checked: the round loop asks,
// outside the lock, whether this agent wants it, and starts asking when it
// does. Cheap: called from the data engine and from PostRefresh.
func (t *catchUpTracker) keyCheck(zone ZoneName) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.keyCheckLocked(zone)
}

func (t *catchUpTracker) keyCheckLocked(zone ZoneName) {
	if t.keyChecks == nil {
		t.keyChecks = map[ZoneName]bool{}
	}
	t.keyChecks[ZoneName(dns.Fqdn(string(zone)))] = true
	t.wakeKeysLocked()
}

// keyRestart starts the zone's entry over: the voting members changed. An
// answer to the round that is out counts for nothing.
func (t *catchUpTracker) keyRestart(zone ZoneName) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	zone = ZoneName(dns.Fqdn(string(zone)))
	if r := t.keyWanted[zone]; r != nil {
		t.keyGen++
		r.gen, r.out, r.decided, r.rounds, r.next = t.keyGen, false, false, 0, time.Now()
	}
	t.keyCheckLocked(zone)
}

// keyAskNowLocked: a zone that became caught up gets its next round at once.
func (t *catchUpTracker) keyAskNowLocked(zone ZoneName) {
	if r := t.keyWanted[zone]; r != nil && !r.out {
		r.next = time.Now()
		t.wakeKeysLocked()
	}
}

func (t *catchUpTracker) wakeKeysLocked() {
	if t.keyWake != nil {
		select {
		case t.keyWake <- struct{}{}:
		default:
		}
	}
}

// keyLoop runs the rounds: the checks that are due, and the rounds whose
// time has come. It runs on the tracker's context, under its WaitGroup.
func (t *catchUpTracker) keyLoop(ctx context.Context) {
	defer t.wg.Done()
	tick := time.NewTicker(keyRoundTick)
	defer tick.Stop()
	for {
		t.keyPass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-t.keyWake:
		}
	}
}

// keyPass does what is due: each check, and each round whose time has come.
// The hooks run outside the lock.
func (t *catchUpTracker) keyPass(ctx context.Context) {
	if t.hooks == nil {
		return
	}
	t.mu.Lock()
	var checks []ZoneName
	for zone := range t.keyChecks {
		checks = append(checks, zone)
	}
	t.keyChecks = nil
	now := time.Now()
	var due []ZoneName
	for zone, r := range t.keyWanted {
		if !r.out && !r.next.After(now) {
			due = append(due, zone)
		}
	}
	t.mu.Unlock()
	sort.Slice(checks, func(i, j int) bool { return checks[i] < checks[j] })
	sort.Slice(due, func(i, j int) bool { return due[i] < due[j] })

	for _, zone := range checks {
		wants := t.hooks.wants(ctx, zone)
		t.mu.Lock()
		if r := t.keyWanted[zone]; wants && r == nil {
			t.keyGen++
			if t.keyWanted == nil {
				t.keyWanted = map[ZoneName]*keyRound{}
			}
			t.keyWanted[zone] = &keyRound{gen: t.keyGen, next: time.Now()}
			due = append(due, zone)
		} else if wants && r != nil && !r.out && r.next.After(time.Now()) {
			// a check is a sign the key may be there now (a KEY
			// operation, a changed apex KEY): the next round asks at once
			r.next = time.Now()
			due = append(due, zone)
		} else if !wants && r != nil {
			delete(t.keyWanted, zone)
		}
		t.mu.Unlock()
	}
	for _, zone := range due {
		if !t.hooks.wants(ctx, zone) {
			t.mu.Lock()
			delete(t.keyWanted, zone)
			t.mu.Unlock()
			continue
		}
		peers := t.hooks.peers(zone)
		serial, known := t.hooks.active(zone)
		decide := t.startKeyRound(ctx, zone, peers, serial, known)
		if decide != nil {
			decide()
		}
	}
}

// startKeyRound sends the zone's round to peers: under the lock, with the
// tracker's context live, each request is registered, queued and given its
// waiter. A peer that is not OPERATIONAL is silence at once. serial is this
// agent's active serial as the round goes out. It returns the decision, to
// run outside the lock, when every answer is in already.
func (t *catchUpTracker) startKeyRound(ctx context.Context, zone ZoneName, peers []AgentId, serial SerialDigest, known bool) func() {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.keyWanted[zone]
	if r == nil || r.out || t.ctx == nil || t.ctx.Err() != nil {
		return nil
	}
	t.keyGen++
	r.gen, r.out, r.decided, r.next = t.keyGen, true, false, time.Time{}
	r.asked, r.answers = append([]AgentId(nil), peers...), map[AgentId]keyReply{}
	r.serial, r.known = serial, known
	for _, peer := range peers {
		if !t.operational(peer) {
			r.answers[peer] = keyReply{outcome: keySilent, detail: "not OPERATIONAL"}
			continue
		}
		kr := &keyReq{zone: zone, peer: peer, gen: r.gen, result: make(chan error, 1), stop: make(chan struct{}),
			cancelWait: func() {}, closeAsk: func() {}}
		t.hooks.prepare(kr)
		if t.keyReqs == nil {
			t.keyReqs = map[AgentId][]*keyReq{}
		}
		t.keyReqs[peer] = append(t.keyReqs[peer], kr)
		t.wg.Add(1)
		go t.keyWaiter(t.ctx, kr)
		t.kickLocked(peer)
	}
	return t.keyDecisionLocked(ctx, zone, r)
}

// nextKeyReq is the peer's next key request to send, if one waits and fewer
// than keyInFlight wait for their answers.
func (t *catchUpTracker) nextKeyReq(peer AgentId) *keyReq {
	t.mu.Lock()
	defer t.mu.Unlock()
	sent := 0
	for _, kr := range t.keyReqs[peer] {
		if kr.sent {
			sent++
		}
	}
	if sent >= keyInFlight {
		return nil
	}
	for _, kr := range t.keyReqs[peer] {
		if !kr.sent {
			kr.sent = true
			return kr
		}
	}
	return nil
}

// keyWaiter waits for one key request's send and its answer, and records
// the outcome. Its window and its registration end on every exit.
func (t *catchUpTracker) keyWaiter(ctx context.Context, kr *keyReq) {
	defer t.wg.Done()
	defer kr.closeAsk()
	defer kr.cancelWait()
	unsent := time.NewTimer(keyUnsentWait)
	defer unsent.Stop()
	var a keyReply
	select {
	case err := <-kr.result:
		if err != nil {
			a = keyReply{outcome: keyNotTaken, detail: err.Error()}
			break
		}
		answered := time.NewTimer(keyAnswerWait)
		defer answered.Stop()
		select {
		case resp := <-kr.answer:
			a = classifyKeyAnswer(resp)
		case <-answered.C:
			kr.cancelWait()
			// an answer that raced the deadline is not lost
			select {
			case resp := <-kr.answer:
				a = classifyKeyAnswer(resp)
			default:
				a = keyReply{outcome: keySilent, detail: fmt.Sprintf("no answer within %s", keyAnswerWait)}
			}
		case <-ctx.Done():
			return
		case <-kr.stop:
			return
		}
	case <-unsent.C:
		a = keyReply{outcome: keySilent, detail: fmt.Sprintf("not sent within %s", keyUnsentWait)}
	case <-ctx.Done():
		return
	case <-kr.stop:
		return
	}
	if decide := t.keyRecord(ctx, kr, a); decide != nil {
		decide()
	}
}

// sameKeyRRset: the two apexes carry the same KEY records.
func sameKeyRRset(a, b *tdns.OwnerData) bool {
	keys := func(o *tdns.OwnerData) []string {
		if o == nil || o.RRtypes == nil {
			return nil
		}
		var out []string
		for _, rr := range o.RRtypes.GetOnlyRRSet(dns.TypeKEY).RRs {
			out = append(out, rr.String())
		}
		sort.Strings(out)
		return out
	}
	ka, kb := keys(a), keys(b)
	if len(ka) != len(kb) {
		return false
	}
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

// classifyKeyAnswer sorts an answer to a key request into the outcomes.
func classifyKeyAnswer(resp *ConfigResponseMsg) keyReply {
	if resp == nil {
		return keyReply{outcome: keySilent, detail: "no answer"}
	}
	if why := resp.Refused(); why != "" {
		return keyReply{outcome: keyRefused, detail: why}
	}
	if len(resp.ConfigData) == 0 {
		return keyReply{outcome: keyNoData}
	}
	switch resp.ConfigData["status"] {
	case "no sig0 key for zone":
		return keyReply{outcome: keyNone, instr: resp.Instr}
	case sig0StatusSeveral:
		return keyReply{outcome: keySeveral}
	}
	return keyReply{outcome: keyGot, data: resp.ConfigData, instr: resp.Instr}
}

// atSerial is a, as the round counts it: a key or a "no key here" stamped
// with another active serial than the round's, or with none, counts for
// nothing (S14).
func (r *keyRound) atSerial(a keyReply) keyReply {
	if a.outcome != keyGot && a.outcome != keyNone {
		return a
	}
	st := a.instr
	switch {
	case !r.known:
		return keyReply{outcome: keyOtherSerial, detail: "this agent knows no active serial"}
	case st == nil || !st.Known:
		return keyReply{outcome: keyOtherSerial, detail: "it tells no active serial"}
	case st.Active != r.serial.Serial || st.ActiveDigest != r.serial.Digest:
		return keyReply{outcome: keyOtherSerial, detail: fmt.Sprintf("it tells active %d, this agent %d", st.Active, r.serial.Serial)}
	}
	return a
}

// keyRecord records a request's outcome, if the request is of the round
// that is out, and takes it off its peer's queue. It returns the round's
// decision, to run outside the lock, when this was the last answer.
func (t *catchUpTracker) keyRecord(ctx context.Context, kr *keyReq, a keyReply) func() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dropKeyReqLocked(kr)
	if kr.sent {
		// a slot is free: the next request to the peer goes out now, not
		// when the peer's sender next wakes for something else
		t.kickLocked(kr.peer)
	}
	r := t.keyWanted[kr.zone]
	if r == nil || r.gen != kr.gen {
		return nil
	}
	r.answers[kr.peer] = r.atSerial(a)
	return t.keyDecisionLocked(ctx, kr.zone, r)
}

func (t *catchUpTracker) dropKeyReqLocked(kr *keyReq) {
	q := t.keyReqs[kr.peer]
	for i, o := range q {
		if o == kr {
			t.keyReqs[kr.peer] = append(q[:i:i], q[i+1:]...)
			break
		}
	}
	if len(t.keyReqs[kr.peer]) == 0 {
		delete(t.keyReqs, kr.peer)
	}
}

// keyDecisionLocked returns the round's decision when every agent asked has
// answered and no decision has started; only one waiter starts it. A round
// whose active serial is not this agent's any more decides nothing: it
// starts over.
func (t *catchUpTracker) keyDecisionLocked(ctx context.Context, zone ZoneName, r *keyRound) func() {
	if r.decided || len(r.answers) < len(r.asked) {
		return nil
	}
	r.decided = true
	gen, serial, known := r.gen, r.serial, r.known
	answers := make(map[AgentId]keyReply, len(r.answers))
	for p, a := range r.answers {
		answers[p] = a
	}
	return func() {
		if now, nowKnown := t.hooks.active(zone); nowKnown != known || now != serial {
			lgAgent.Info("the zone's active serial changed while its key round was out: the round starts over", "zone", zone,
				"was", serial.Serial, "now", now.Serial)
			t.keyRestart(zone)
			return
		}
		done := t.hooks.decide(ctx, zone, answers)
		t.keyRoundEnded(zone, gen, done)
	}
}

// keyRoundEnded drops the zone's entry when the key is held, or schedules
// its next round.
func (t *catchUpTracker) keyRoundEnded(zone ZoneName, gen uint64, done bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.keyWanted[zone]
	if r == nil || r.gen != gen {
		return
	}
	if done {
		delete(t.keyWanted, zone)
		return
	}
	delay := keyRoundEvery
	if r.rounds < len(keyRoundDelays) {
		delay = keyRoundDelays[r.rounds]
	}
	r.rounds++
	r.out, r.next = false, time.Now().Add(delay)
	if t.keyLogs.due("again " + string(zone)) {
		lgAgent.Warn("no SIG(0) key yet, asking again", "zone", zone, "answers", answersLine(r.answers), "next", delay)
	}
}

// forgetKeyReqsLocked ends a forgotten peer's key requests: each counts as
// silence in its round, and the decisions that become due are returned.
func (t *catchUpTracker) forgetKeyReqsLocked(ctx context.Context, peer AgentId) []func() {
	var decisions []func()
	for _, kr := range t.keyReqs[peer] {
		close(kr.stop)
		if r := t.keyWanted[kr.zone]; r != nil && r.gen == kr.gen {
			r.answers[peer] = keyReply{outcome: keySilent, detail: "the peer was removed"}
			if d := t.keyDecisionLocked(ctx, kr.zone, r); d != nil {
				decisions = append(decisions, d)
			}
		}
	}
	delete(t.keyReqs, peer)
	return decisions
}

// keyWantedZones: the zones this agent asks the key for (status, tests).
func (t *catchUpTracker) keyWantedZones() []ZoneName {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []ZoneName
	for zone := range t.keyWanted {
		out = append(out, zone)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
