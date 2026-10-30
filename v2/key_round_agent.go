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
		peers:   conf.zoneKeyPeerIDs,
		prepare: conf.prepareKeyReq,
		send:    conf.sendKeyReq,
		decide:  conf.decideZoneKey,
	}
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
// uses a key, and this agent does not hold the zone's key. When it holds it,
// every other active key for the zone is retired. Reads the keystore and
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
	var wants, retired bool
	_ = conf.keySetupLocked(zone, func() error {
		zk, err := readZoneKey(kdb, zone)
		switch {
		case err != nil:
			// the round's decision reads the keystore again
			lgAgent.Warn("the zone's SIG(0) keys could not be read; asking for the key", "zone", zone, "err", err)
			wants = true
		case zk.several():
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
	return wants
}

// zoneKeyPeerIDs are the agents asked for the zone's key (zoneKeyPeers): the
// voting members other than this agent, and every agent the zone lists ON
// with no role.
func (conf *Config) zoneKeyPeerIDs(zone ZoneName) []AgentId {
	ar := conf.InternalMp.AgentRegistry
	if ar == nil || ar.LocalAgent == nil {
		return nil
	}
	var agents []*Agent
	if zad, err := ar.GetZoneAgentData(zone); err == nil {
		agents = zad.Agents
	}
	var ids []AgentId
	for _, a := range zoneKeyPeers(zone, agents, AgentId(ar.LocalAgent.Identity), ar.roleLessKeyHolders(zone)) {
		ids = append(ids, a.ID)
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
	if zk.held != nil {
		return true, false // held meanwhile: the leader's set-up publishes it
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
