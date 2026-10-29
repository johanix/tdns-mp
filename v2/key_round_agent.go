/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// The agent's parts of the key rounds (step 7b, key_rounds.go): whether this
// agent wants the zone's SIG(0) key, whom it asks, how a request goes out,
// and what a round's answers decide.

// hourlyLog says when a line is due: the first time, then once an hour.
type hourlyLog struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (h *hourlyLog) due(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.last == nil {
		h.last = map[string]time.Time{}
	}
	now := time.Now()
	if last, ok := h.last[key]; ok && now.Sub(last) < time.Hour {
		return false
	}
	h.last[key] = now
	return true
}

// keyRoundHooks are the agent's hooks of the key rounds.
func (conf *Config) keyRoundHooks() *keyHooks {
	return &keyHooks{
		wants:   conf.wantsZoneKey,
		peers:   conf.keyRoundPeers,
		active:  conf.activeSerial,
		prepare: conf.prepareKeyReq,
		send:    conf.sendKeyReq,
		decide:  conf.decideZoneKey,
	}
}

// activeSerial is this agent's active serial for the zone, if it knows one:
// a key answer counts only at it (S14).
func (conf *Config) activeSerial(zone ZoneName) (SerialDigest, bool) {
	st, ok := conf.InternalMp.Instructions.stampOf(string(zone))
	return SerialDigest{Serial: st.Active, Digest: st.ActiveDigest}, ok && st.Known
}

// zoneKeyDB is the keystore that signs the zone's UPDATE: the zone's own,
// else the agent's.
func (conf *Config) zoneKeyDB(zone ZoneName) *tdns.KeyDB {
	if mpzd, ok := Zones.Get(string(zone)); ok && mpzd != nil && mpzd.ZoneData != nil && mpzd.KeyDB != nil {
		return mpzd.KeyDB
	}
	if conf.Config != nil {
		return conf.Config.Internal.KeyDB
	}
	return nil
}

// keySetupLocked runs f under the zone's key-setup lock (inKeySetup).
func (conf *Config) keySetupLocked(zone ZoneName, f func() error) error {
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		return lem.inKeySetup(zone, f)
	}
	return f()
}

func (conf *Config) localAgentID() AgentId {
	if ar := conf.InternalMp.AgentRegistry; ar != nil && ar.LocalAgent != nil {
		return AgentId(ar.LocalAgent.Identity)
	}
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		return lem.localID
	}
	return ""
}

func keyTags(keys []*dns.KEY) []uint16 {
	var out []uint16
	for _, k := range keys {
		out = append(out, k.KeyTag())
	}
	return out
}

// logSeveralKeys: the apex carries several KEYs, so no local key is the
// zone's key, and nothing is asked, imported, retired or made.
func (conf *Config) logSeveralKeys(zone ZoneName, zk *zoneKey) {
	if conf.InternalMp.keyLogs.due("several " + string(zone)) {
		lgAgent.Error("the zone publishes several SIG(0) KEYs: an operator has to leave one", "zone", zone, "keyids", keyTags(zk.published))
	}
}

// wantsZoneKey: this agent votes in the zone, the zone has loaded here and
// uses a key, and this agent does not hold the zone's key, or leads the zone
// and the parent does not trust the key yet (keyPending, S14). When it holds
// it, every other active key for the zone is retired. Reads the keystore and
// asks the resolver: run by the round loop, never under the tracker's lock.
func (conf *Config) wantsZoneKey(ctx context.Context, zone ZoneName) bool {
	in := instructionsFor(zone)
	if !hasHSYNC3(in) || !votesIn(in, conf.localAgentID()) {
		return false
	}
	// a parent that takes no UPDATE needs no key; one whose DSYNC records
	// could not be read may, so the asking goes on
	if uses, known := conf.zoneKeyUse(ctx, zone); known && !uses {
		return false
	}
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return false
	}
	var wants, retired, several bool
	_ = conf.keySetupLocked(zone, func() error {
		zk, err := readZoneKey(kdb, zone)
		switch {
		case err != nil:
			// the round's decision reads the keystore again
			lgAgent.Warn("the zone's SIG(0) keys could not be read; asking for the key", "zone", zone, "err", err)
			wants = true
		case zk.several():
			several = true
			conf.logSeveralKeys(zone, zk)
		case zk.held == nil:
			wants = true
		case len(zk.others()) > 0:
			only, err := retireOtherActiveKeys(kdb, zone, zk)
			if err != nil || !only {
				lgAgent.Warn("an active SIG(0) key that is not the zone's key could not be retired; the sync with the parent waits", "zone", zone, "keyid", zk.held.keyid, "err", err)
			}
			retired = only
		}
		return nil
	})
	if retired {
		conf.releaseKeyHold(ctx, zone)
	}
	// at the leader the entry stays until the key is usable: its rounds
	// offer the key again (S14)
	return wants || (!several && conf.keyPending(ctx, zone))
}

// keyRoundPeers are the agents a round asks: none at a leader that holds the
// zone's key, whose round only offers it to the parent again (S14), and
// otherwise zoneKeyPeerIDs.
func (conf *Config) keyRoundPeers(zone ZoneName) []AgentId {
	if kdb := conf.zoneKeyDB(zone); kdb != nil {
		if zk, err := readZoneKey(kdb, zone); err == nil && zk.held != nil {
			return nil
		}
	}
	return conf.zoneKeyPeerIDs(zone)
}

// zoneKeyPeerIDs are the agents asked for the zone's key (zoneKeyPeers): the
// voting members other than this agent, and every agent the zone lists ON
// with no role; during a transition, every voting member under both its
// serials too (design 6, S14).
func (conf *Config) zoneKeyPeerIDs(zone ZoneName) []AgentId {
	ar := conf.InternalMp.AgentRegistry
	if ar == nil || ar.LocalAgent == nil {
		return nil
	}
	var agents []*Agent
	if zad, err := ar.GetZoneAgentData(zone); err == nil {
		agents = zad.Agents
	}
	self := AgentId(ar.LocalAgent.Identity)
	var ids []AgentId
	for _, a := range zoneKeyPeers(zone, agents, self, ar.roleLessKeyHolders(zone)) {
		ids = append(ids, a.ID)
	}
	for _, id := range conf.InternalMp.Instructions.transitionVoters(string(zone)) {
		if core.EqualNames(dns.Fqdn(id), dns.Fqdn(string(self))) ||
			slices.ContainsFunc(ids, func(p AgentId) bool { return core.EqualNames(dns.Fqdn(string(p)), dns.Fqdn(id)) }) {
			continue
		}
		if agent, err := ar.GetAgentInfo(AgentId(id)); err == nil {
			ids = append(ids, agent.ID)
		}
	}
	if conf.InternalMp.keyLogs.due("asking " + string(zone)) {
		lgAgent.Info("asking for the zone's SIG(0) key: this agent does not hold it", "zone", zone, "asked", ids,
			"published", keyTags(publishedKeys(zone)))
	}
	return ids
}

// prepareKeyReq registers the request's answer and opens its window for the
// key's hand-over (keyAsks), with the distribution ID whose confirmation is
// let in, before the request is queued. Under the tracker's lock: the
// waiters and the window are leaf locks.
func (conf *Config) prepareKeyReq(kr *keyReq) {
	if msgQs := conf.InternalMp.MsgQs; msgQs != nil {
		kr.nonce = newRfiNonce()
		kr.answer, kr.cancelWait = msgQs.configWaiters.register(rfiWaitKey(string(kr.peer), string(kr.zone), "sig0key", kr.nonce))
	}
	if tm := conf.InternalMp.MPTransport; tm != nil {
		kr.distID = transport.GenerateDistributionID()
		kr.closeAsk = tm.keyAsks.start(string(kr.peer), string(kr.zone))
		tm.keyAsks.expectConfirm(string(kr.peer), kr.distID)
	}
}

// sendKeyReq sends the request, an RFI CONFIG sig0key with the round's nonce
// and distribution ID, and returns at the peer's acknowledgement.
func (conf *Config) sendKeyReq(ctx context.Context, kr *keyReq) error {
	ar := conf.InternalMp.AgentRegistry
	if ar == nil || ar.LocalAgent == nil {
		return fmt.Errorf("this agent has no registry")
	}
	if kr.nonce == "" {
		return fmt.Errorf("this agent has no message queues")
	}
	agent, err := ar.GetAgentInfo(kr.peer)
	if err != nil {
		return err
	}
	_, err = ar.sendRfiToAgentCtx(ctx, agent, &AgentMsgPost{
		MessageType:    AgentMsgRfi,
		OriginatorID:   AgentId(ar.LocalAgent.Identity),
		YourIdentity:   kr.peer,
		Zone:           kr.zone,
		RfiType:        "CONFIG",
		RfiSubtype:     "sig0key",
		DistributionID: kr.distID,
		Nonce:          kr.nonce,
	})
	return err
}

// answersLine is a round's answers, for a log line.
func answersLine(answers map[AgentId]keyReply) string {
	var parts []string
	for _, peer := range sortedPeers(answers) {
		a := answers[peer]
		s := string(peer) + "=" + a.outcome
		if a.detail != "" {
			s += " (" + a.detail + ")"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func sortedPeers(answers map[AgentId]keyReply) []AgentId {
	peers := make([]AgentId, 0, len(answers))
	for p := range answers {
		peers = append(peers, p)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i] < peers[j] })
	return peers
}

// decideZoneKey is what a round's answers decide, under the zone's key-setup
// lock. A key handed over is imported. At the agent that leads the zone it
// is then published, and its poll started; or, when every agent asked has
// said it holds none, every voting member was asked, the zone is caught up
// and publishes no KEY, a key is made. A zone that publishes a KEY nobody
// holds is reported, not given a new one. It reports whether the zone's key
// is held now, or the round is over for good.
func (conf *Config) decideZoneKey(ctx context.Context, zone ZoneName, answers map[AgentId]keyReply) bool {
	var done, askSync bool
	_ = conf.keySetupLocked(zone, func() error {
		done, askSync = conf.decideZoneKeyLocked(ctx, zone, answers)
		return nil
	})
	if askSync {
		conf.requestDelegationSync(ctx, string(zone), "the zone's SIG(0) key is held now")
	}
	// a sync that came while a count was up is asked for when the hold is
	// over, not only at the next tick
	conf.releaseKeyHold(ctx, zone)
	return done
}

func (conf *Config) decideZoneKeyLocked(ctx context.Context, zone ZoneName, answers map[AgentId]keyReply) (done, askSync bool) {
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return false, false
	}
	hdb := NewHsyncDB(kdb)
	lem := conf.InternalMp.LeaderElectionManager
	leads := lem != nil && lem.IsLeader(zone)
	zk, err := readZoneKey(kdb, zone)
	if err != nil {
		lgAgent.Warn("the zone's SIG(0) keys could not be read; asking again", "zone", zone, "err", err)
		return false, false
	}
	if zk.several() {
		conf.logSeveralKeys(zone, zk)
		return true, false // a refresh that leaves one KEY checks again
	}
	// A key LOST (S14) stays so until it is held, or the zone publishes no
	// KEY: a later round with a silent peer does not end it
	if zk.held != nil || len(zk.published) == 0 {
		conf.InternalMp.keyPolls.setLost(zone, false, 0)
	}
	if zk.held != nil {
		// held meanwhile: the leader's set-up publishes it. A leader keeps
		// the entry, and offers the key again, until the parent trusts it
		// (S14)
		return !(leads && conf.reofferZoneKey(ctx, zone, zk)), false
	}

	// The leader's sync waits from when a key is taken or made until the
	// poll this decision starts has ended (keyPolls): counted before the
	// key is taken or made, and only then.
	var tk *keyPollToken
	unpublished := false
	begin := func() {
		if leads && tk == nil {
			tk = conf.InternalMp.keyPolls.begin(zone)
		}
	}
	defer func() { tk.end(unpublished) }()

	for _, peer := range sortedPeers(answers) {
		a := answers[peer]
		if a.outcome != keyGot {
			continue
		}
		begin()
		if err := importSig0KeyFromPeer(hdb, string(zone), a.data); err != nil {
			lgAgent.Error("failed to import SIG(0) key from peer", "zone", zone, "peer", peer, "err", err)
			answers[peer] = keyReply{outcome: keyNotImported, detail: err.Error()}
			continue
		}
		lgAgent.Info("imported SIG(0) key from peer", "zone", zone, "peer", peer)
		if !leads {
			return true, false // a member that does not lead publishes nothing
		}
		unpublished = true // a key taken counts as unpublished until it is
		if err := conf.publishZoneKey(ctx, zone, tk, false, 0); err != nil {
			if !errors.Is(err, errLeadMoved) && !errors.Is(err, errHeldDuringTransition) {
				lgAgent.Error("the SIG(0) key taken could not be published; the sync with the parent waits", "zone", zone, "err", err)
			}
			return true, false
		}
		unpublished = false
		return true, true
	}

	if !leads {
		return false, false
	}
	allNone := len(answers) > 0 || len(votingPeers(zone, conf.localAgentID())) == 0
	for _, a := range answers {
		if a.outcome != keyNone {
			allNone = false
		}
	}
	for _, id := range votingPeers(zone, conf.localAgentID()) {
		if !slices.ContainsFunc(sortedPeers(answers), func(p AgentId) bool { return isAmong([]string{string(p)}, id) }) {
			allNone = false // a voting member not asked has not said it holds none
		}
	}
	if !allNone {
		return false, false
	}
	if len(zk.published) > 0 {
		conf.InternalMp.keyPolls.setLost(zone, true, zk.published[0].KeyTag())
		if conf.InternalMp.keyLogs.due("lost " + string(zone)) {
			lgAgent.Error("the zone publishes a SIG(0) key that no voting member holds: an operator has to act",
				"zone", zone, "keyid", zk.published[0].KeyTag())
		}
		return false, false
	}
	if t := conf.InternalMp.CatchUp; t != nil {
		if ok, _ := t.CaughtUp(zone); !ok {
			return false, false // deciding that no key exists waits for the catch-up
		}
	}
	// and for the transition's end: nothing new starts while the zone is
	// frozen (plan S6)
	if held, why := conf.syncHeld(string(zone), syncOther); held {
		lgAgent.Info("deciding that the zone has no SIG(0) key waits for the transition", "zone", zone, "phase", why)
		return false, false
	}
	// a key is made only for a parent known to take UPDATE
	if uses, known := conf.zoneKeyUse(ctx, zone); !known {
		return false, false
	} else if !uses {
		return true, false
	}
	begin()
	made, madeKeyid, err := conf.makeZoneKey(hdb, zone, len(zk.active) == 0)
	if err != nil {
		lgAgent.Error("the zone's SIG(0) key could not be made", "zone", zone, "err", err)
		return false, false
	}
	unpublished = true
	if err := conf.publishZoneKey(ctx, zone, tk, made, madeKeyid); err != nil {
		if made && errors.Is(err, errLeadMoved) {
			unpublished = false // the key is gone
		} else if !errors.Is(err, errLeadMoved) && !errors.Is(err, errHeldDuringTransition) {
			lgAgent.Error("the SIG(0) key made could not be published; the sync with the parent waits", "zone", zone, "err", err)
		}
		return true, false
	}
	unpublished = false
	return true, true
}

// keyOfferEvery paces the leader's offers of a key the parent has not taken
// (S14). A variable, so that a test can shorten it.
var keyOfferEvery = 5 * time.Minute

// reofferZoneKey is a round's word at the leader that holds the zone's key:
// while the parent does not trust it (keyPending) the key is offered again,
// at most every keyOfferEvery and not while a poll of it runs, under the
// zone's parent context (launchKeyPoll); a key whose publication failed is
// published again, which starts its poll. It reports whether the key is
// still pending: the round's entry stays until the key is usable (S14).
// Under the zone's key-setup lock.
func (conf *Config) reofferZoneKey(ctx context.Context, zone ZoneName, zk *zoneKey) bool {
	if !conf.keyPending(ctx, zone) {
		return false
	}
	b := &conf.InternalMp.keyPolls
	running, unpublished, _ := b.state(zone)
	if running > 0 || time.Since(b.lastOffer(zone)) < keyOfferEvery || zk.held.key == nil {
		return true
	}
	lgAgent.Info("the parent has not taken the zone's SIG(0) key, offering it again", "zone", zone, "keyid", zk.held.keyid,
		"parent_state", edns0.KeyStateToString(zk.held.parentState), "in", keyOfferEvery)
	if unpublished {
		tk := b.begin(zone)
		err := conf.publishZoneKey(ctx, zone, tk, false, 0)
		tk.end(err != nil && !errors.Is(err, errLeadMoved))
		return true
	}
	conf.launchKeyPoll(ctx, nil, zone, string(zone), zk.held.keyid, zk.held.key.Algorithm)
	return true
}
