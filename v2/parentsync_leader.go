/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"fmt"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

var lgElect = tdns.Logger("elect")

func NewLeaderElectionManager(localID AgentId, leaderTTL time.Duration, broadcastFunc func(ZoneName, string, map[string][]string) error) *LeaderElectionManager {
	return &LeaderElectionManager{
		elections:        make(map[ZoneName]*LeaderElection),
		pendingElections: make(map[ZoneName]bool),
		groupElections:   make(map[string]*LeaderElection),
		localID:          localID,
		leaderTTL:        leaderTTL,
		broadcastFunc:    broadcastFunc,
	}
}

// SetProviderGroupManager sets the provider group manager for group-based elections.
// The manager then also reports each zone that enters a group (zoneJoinedGroup).
func (lem *LeaderElectionManager) SetProviderGroupManager(pgm *ProviderGroupManager) {
	lem.providerGroupMgr = pgm
	if pgm != nil {
		pgm.SetOnZoneJoinedGroup(lem.zoneJoinedGroup)
	}
}

// SetOperationalPeersFunc sets the callback used to count operational peers for re-election.
func (lem *LeaderElectionManager) SetOperationalPeersFunc(f func(zone ZoneName) int) {
	lem.operationalPeersFunc = f
}

// SetConfiguredPeersFunc sets the callback that returns the number of configured
// peers for a zone (from HSYNC3 records, minus self).
func (lem *LeaderElectionManager) SetConfiguredPeersFunc(f func(zone ZoneName) int) {
	lem.configuredPeersFunc = f
}

// configuredPeers returns the number of configured peers for a zone.
func (lem *LeaderElectionManager) configuredPeers(zone ZoneName) int {
	if lem.configuredPeersFunc != nil {
		return lem.configuredPeersFunc(zone)
	}
	if lem.operationalPeersFunc != nil {
		return lem.operationalPeersFunc(zone)
	}
	return 0
}

// SetOnLeaderElected sets the callback invoked when the local agent wins an
// election, renews its lease, or leads a zone whose delegation sync comes back
// to the agents (delegationSyncGivenBack). Each of those runs it in a goroutine
// of its own. For one zone they run one at a time, so that two leader setups
// never both find no SIG(0) key and each make one.
func (lem *LeaderElectionManager) SetOnLeaderElected(f func(zone ZoneName) error) {
	lem.onLeaderElected = func(zone ZoneName) error {
		return lem.inKeySetup(zone, func() error { return f(zone) })
	}
}

// inKeySetup runs f with the zone's key-setup lock held. Every setup of a
// zone's SIG(0) key takes it: the leader's after an election, a renewal or a
// sync given back (SetOnLeaderElected), the one at an arrival
// (SetOnZoneJoined), and a key round's decision (decideZoneKey). For one zone
// they run one at a time, so that two of them never both find no key and
// each make one, and a setup's clean-up of a key it made for a lead that
// moved never takes a key another setup has just adopted. It is taken once
// per setup and never nested: a sync.Mutex is not re-entrant.
func (lem *LeaderElectionManager) inKeySetup(zone ZoneName, f func() error) error {
	mu, _ := lem.keySetups.LoadOrStore(zone, new(sync.Mutex))
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()
	return f()
}

// SetOnZoneJoined sets the callback invoked when a zone joins a provider
// group that the local agent already leads (zoneJoinedGroup). It is not the
// election's callback: a zone that arrives has had a leader before, and what
// that leader made for it, its SIG(0) key first of all, is not to be made
// again. With no callback set an arrival asks nothing.
func (lem *LeaderElectionManager) SetOnZoneJoined(f func(zone ZoneName) error) {
	lem.onZoneJoined = func(zone ZoneName) error {
		return lem.inKeySetup(zone, func() error { return f(zone) })
	}
}

// StartGroupElection initiates a leader election for a provider group.
func (lem *LeaderElectionManager) StartGroupElection(groupHash string, members []string, zones []ZoneName) {
	lem.startGroupElection(groupHash, members, zones, nil)
}

// startGroupElection is StartGroupElection, for a caller that is a timer when
// armed is set: a lease renewal, or the retry after an election that was
// aborted. Such a timer was armed in a term, and it acts only while the
// election still stands there: when a newer term is in, or an election is
// running, another member got there first and this one starts nothing. Without
// that, every member's renewal and every member's retry minted a term of its
// own, and a lease renewal was two or three elections in one second (#120).
func (lem *LeaderElectionManager) startGroupElection(groupHash string, members []string, zones []ZoneName, armed *uint64) {
	// Only a voting member starts an election, whoever asks for it (the
	// membership design, 4.4). Asked of the group as the group manager has
	// it now; members is the test only where there is no group manager.
	voters, known := lem.groupVoters(groupHash, members)
	if !known {
		lgElect.Debug("no election started: the provider group is gone", "group", shortHash(groupHash))
		return
	}
	if !isAmong(voters, lem.localID) {
		lgElect.Debug("no election started: this agent does not vote in the zone", "group", shortHash(groupHash))
		return
	}
	members = voters

	expectedPeers := len(members) - 1 // minus self

	lem.mu.Lock()
	le, ok := lem.groupElections[groupHash]
	if !ok {
		le = &LeaderElection{
			Zone:     ZoneName(groupHash),
			Votes:    make(map[AgentId]uint32),
			Confirms: make(map[AgentId]AgentId),
		}
		lem.groupElections[groupHash] = le
	}
	lem.mu.Unlock()

	le.mu.Lock()

	if armed != nil && (le.Active || le.Term != *armed) {
		term := le.Term
		le.mu.Unlock()
		lgElect.Debug("group election has moved on since this timer was armed, starting none",
			"group", groupHash[:8], "armed", *armed, "term", term)
		return
	}

	// Single agent: self-elect immediately
	if expectedPeers == 0 {
		lem.noteLeaderLocked(le, lem.localID, time.Now())
		le.Leader = lem.localID
		le.leaderTerm = le.Term
		le.LeaderExpiry = time.Now().Add(lem.leaderTTL)
		le.Active = false
		lgElect.Info("single agent in group, self-elected as leader", "group", groupHash[:8])
		lem.scheduleGroupReelection(le, groupHash, members)
		le.askedTerm = le.Term // asked below; gossip echoing this term asks nothing more
		le.mu.Unlock()

		if lem.onLeaderElected != nil {
			for _, zone := range zones {
				go func(z ZoneName) {
					if err := lem.onLeaderElected(z); err != nil {
						lgElect.Error("onLeaderElected callback failed", "zone", z, "group", groupHash[:8], "error", err)
					}
				}(zone)
			}
		}
		return
	}

	// Reset election state
	le.Active = true
	le.Term++
	le.MyVote = rand.Uint32()
	le.Votes = map[AgentId]uint32{lem.localID: le.MyVote}
	le.Confirms = make(map[AgentId]AgentId)
	le.ExpectedPeers = expectedPeers
	term := le.Term
	le.takeEarlyVotes(term, false)
	vote := le.MyVote

	if le.VoteTimer != nil {
		le.VoteTimer.Stop()
	}
	if le.ConfirmTimer != nil {
		le.ConfirmTimer.Stop()
	}

	le.VoteTimer = time.AfterFunc(5*time.Second, func() {
		lem.onGroupVoteTimeout(groupHash, term, members, zones)
	})

	le.mu.Unlock()

	lgElect.Info("starting group election", "group", groupHash[:8], "term", term, "peers", expectedPeers, "zones", len(zones))

	if len(zones) > 0 {
		// Include initiator's vote in ELECT-CALL to avoid out-of-order
		// delivery (separate CALL and VOTE are sent in goroutines and
		// can arrive in any order on the receiver).
		records := map[string][]string{
			"_term":  {strconv.FormatUint(term, 10)},
			"_group": {groupHash},
			"_vote":  {strconv.FormatUint(uint64(vote), 10)},
		}
		if err := lem.broadcastFunc(zones[0], "ELECT-CALL", records); err != nil {
			lgElect.Error("failed to broadcast group ELECT-CALL", "group", groupHash[:8], "err", err)
		}
	}
}

// leaveElectionToGroup says, in the log, that a zone's election is its
// provider group's, and that nothing is started for the zone here. The
// group's election is called when the group becomes mutually OPERATIONAL
// (wireAgentGossipCallbacks), and a zone that arrives in a group that has
// its leader is taken up by that leader (zoneJoinedGroup).
//
// It was DeferGroupElection, and marked the group in a map of elections to
// start once the group was OPERATIONAL. Nothing ever read the map: the
// election of a group that becomes OPERATIONAL is called whether the group
// was marked or not (tdns-mp #183).
func (lem *LeaderElectionManager) leaveElectionToGroup(groupHash string) {
	lgElect.Info("no election started here, the zone's election is its provider group's", "group", groupHash[:8])
}

// groupVoters returns the group's voting members as the provider group
// manager has them now, and false when it has no such group. Without a
// group manager, as in a test, they are members. (A group that is gone is
// dropped by groupGone, which the manager calls after its recompute.)
func (lem *LeaderElectionManager) groupVoters(groupHash string, members []string) ([]string, bool) {
	if lem.providerGroupMgr == nil {
		return members, true
	}
	pg := lem.providerGroupMgr.GetGroup(groupHash)
	if pg == nil {
		return nil, false
	}
	return pg.VotingMembers, true
}

// isAmong: whether id is one of a group's voting members. Names are compared
// as canonical names, in any case and as FQDNs, as the authorization of a
// sender is: the members come from zone data and carry the trailing dot, an
// identity from a config or a message need not. One comparison for the sender and for this agent itself: with two,
// an agent whose configured identity lacked the dot was counted by its peers
// and took itself for an observer.
func isAmong(members []string, id AgentId) bool {
	return slices.ContainsFunc(members, func(m string) bool { return strings.EqualFold(dns.Fqdn(m), dns.Fqdn(string(id))) })
}

// HandleGroupMessage dispatches an election message that carries a _group record.
func (lem *LeaderElectionManager) HandleGroupMessage(groupHash string, senderID AgentId, rfiType string, records map[string][]string) {
	// Find group metadata for callbacks. Quorum/initiator logic
	// uses voting members only — non-voting roles (auditors) may
	// receive the broadcast but must not be counted.
	var members []string
	var zones []ZoneName
	if lem.providerGroupMgr != nil {
		pg := lem.providerGroupMgr.GetGroup(groupHash)
		if pg != nil {
			members = pg.VotingMembers
			zones = pg.Zones
		}
	}

	if len(members) == 0 {
		lgElect.Warn("group election: no voting members found, skipping", "groupHash", groupHash)
		return
	}

	// A CALL, a VOTE or a CONFIRM counts only from a voting member. The
	// transport has admitted the sender as a peer, which is not the same
	// thing: an auditor gets the broadcast and observes. Checked once, here,
	// for all three and so for a vote kept ahead of its CALL too
	// (tdns-mp #143).
	if !isAmong(members, senderID) {
		lgElect.Warn("group election: message from a sender that is not a voting member, dropped",
			"group", groupHash[:8], "type", rfiType, "sender", senderID, "term", parseUint64(records, "_term"))
		return
	}

	// If we're not a voting member ourselves, we still want to
	// observe the protocol (useful for auditors auditing) but we
	// must not vote, initiate, or be counted in the quorum.
	if !isAmong(members, lem.localID) {
		lgElect.Info("leader election observed (not a voting member, no participation)",
			"group", groupHash[:8], "type", rfiType, "initiator", senderID, "term", parseUint64(records, "_term"))
		return
	}

	// The election's entry is made only here, for a group that is known and
	// in which this agent votes: a late message for a group that is gone
	// must not bring its entry back (groupGone).
	lem.mu.Lock()
	le, ok := lem.groupElections[groupHash]
	if !ok {
		le = &LeaderElection{
			Zone:     ZoneName(groupHash),
			Votes:    make(map[AgentId]uint32),
			Confirms: make(map[AgentId]AgentId),
		}
		lem.groupElections[groupHash] = le
	}
	lem.mu.Unlock()

	switch rfiType {
	case "ELECT-CALL":
		lem.handleGroupCall(le, groupHash, senderID, records, members, zones)
	case "ELECT-VOTE":
		lem.handleGroupVote(le, groupHash, senderID, records, members, zones)
	case "ELECT-CONFIRM":
		lem.handleGroupConfirm(le, groupHash, senderID, records, members, zones)
	}
}

func (lem *LeaderElectionManager) handleGroupCall(le *LeaderElection, groupHash string, senderID AgentId, records map[string][]string, members []string, zones []ZoneName) {
	term := parseUint64(records, "_term")
	le.mu.Lock()

	if le.Active && le.Term >= term {
		le.mu.Unlock()
		return
	}

	le.Active = true
	le.Term = term
	le.MyVote = rand.Uint32()
	// Record both our own vote and the initiator's vote (included in ELECT-CALL).
	le.Votes = map[AgentId]uint32{lem.localID: le.MyVote}
	initiatorVote := uint32(parseUint64(records, "_vote"))
	if initiatorVote != 0 {
		le.Votes[senderID] = initiatorVote
	}
	le.Confirms = make(map[AgentId]AgentId)
	le.ExpectedPeers = len(members) - 1
	// A vote for this term that got here before the CALL.
	le.takeEarlyVotes(term, true)
	vote := le.MyVote

	if le.VoteTimer != nil {
		le.VoteTimer.Stop()
	}

	// Check if we already have all votes (2-member group: initiator's
	// vote was in the CALL, plus our own).
	votes, expected := len(le.Votes), le.ExpectedPeers+1
	allVotes := votes >= expected

	// With every vote in there is nothing to time out. The timer is armed
	// here, under the lock, or not at all: once the lock is released it can
	// be a newer term's.
	if !allVotes {
		le.VoteTimer = time.AfterFunc(5*time.Second, func() {
			lem.onGroupVoteTimeout(groupHash, term, members, zones)
		})
	}
	le.mu.Unlock()

	// The counts were taken under the lock: a vote can arrive while this logs.
	lgElect.Info("joining group election", "group", groupHash[:8], "term", term, "from", senderID,
		"votes", votes, "expected", expected)

	// Broadcast our vote to all peers.
	if len(zones) > 0 {
		voteRecords := map[string][]string{
			"_vote":  {strconv.FormatUint(uint64(vote), 10)},
			"_term":  {strconv.FormatUint(term, 10)},
			"_group": {groupHash},
		}
		if err := lem.broadcastFunc(zones[0], "ELECT-VOTE", voteRecords); err != nil {
			lgElect.Error("failed to broadcast group ELECT-VOTE", "group", groupHash[:8], "err", err)
		}
	}

	// If we already have all votes, proceed to confirm immediately.
	if allVotes {
		go lem.determineAndConfirmGroup(groupHash, term, members, zones)
	}
}

func (lem *LeaderElectionManager) handleGroupVote(le *LeaderElection, groupHash string, senderID AgentId, records map[string][]string, members []string, zones []ZoneName) {
	term := parseUint64(records, "_term")
	vote := uint32(parseUint64(records, "_vote"))

	le.mu.Lock()
	defer le.mu.Unlock()

	if !le.Active || le.Term != term {
		if le.keepEarlyVote(term, senderID, vote) {
			lgElect.Debug("group vote for a term not joined yet, kept for its CALL",
				"group", groupHash[:8], "from", senderID, "term", term, "our_term", le.Term)
		} else {
			lgElect.Debug("ignoring group vote for wrong term",
				"group", groupHash[:8], "from", senderID, "expected", le.Term, "got", term)
		}
		return
	}

	le.Votes[senderID] = vote
	lgElect.Info("received group vote", "group", groupHash[:8], "from", senderID, "votes", len(le.Votes), "expected", le.ExpectedPeers+1)

	if len(le.Votes) >= le.ExpectedPeers+1 {
		if le.VoteTimer != nil {
			le.VoteTimer.Stop()
		}
		go lem.determineAndConfirmGroup(groupHash, term, members, zones)
	}
}

func (lem *LeaderElectionManager) handleGroupConfirm(le *LeaderElection, groupHash string, senderID AgentId, records map[string][]string, members []string, zones []ZoneName) {
	term := parseUint64(records, "_term")
	winner := AgentId(parseString(records, "_winner"))

	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}

	le.Confirms[senderID] = winner

	if len(le.Confirms) >= le.ExpectedPeers+1 {
		if le.ConfirmTimer != nil {
			le.ConfirmTimer.Stop()
		}
		le.mu.Unlock()
		lem.finalizeGroupElection(groupHash, term, members, zones)
		return
	}
	le.mu.Unlock()
}

func (lem *LeaderElectionManager) onGroupVoteTimeout(groupHash string, term uint64, members []string, zones []ZoneName) {
	lem.mu.RLock()
	le := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if le == nil {
		return
	}

	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}
	collected := len(le.Votes)
	expected := le.ExpectedPeers + 1
	if collected < expected {
		le.Active = false
		le.mu.Unlock()
		lgElect.Warn("group election aborted: not all members voted, retrying",
			"group", groupHash[:8], "term", term, "votes", collected, "expected", expected)
		lem.retryGroupElection(le, groupHash, term)
		return
	}
	le.mu.Unlock()
	lem.determineAndConfirmGroup(groupHash, term, members, zones)
}

func (lem *LeaderElectionManager) determineAndConfirmGroup(groupHash string, term uint64, members []string, zones []ZoneName) {
	lem.mu.RLock()
	le := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if le == nil {
		return
	}

	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}

	winner := determineWinner(le.Votes)
	le.Confirms[lem.localID] = winner
	// The peers' confirms can be in already: a peer confirms the moment it
	// holds every vote, and its CONFIRM may be handled before this runs. Ours
	// then completes the set, and nothing else would finalize the election
	// before the confirm timer did.
	complete := len(le.Confirms) >= le.ExpectedPeers+1

	if le.ConfirmTimer != nil {
		le.ConfirmTimer.Stop()
	}
	if !complete {
		le.ConfirmTimer = time.AfterFunc(5*time.Second, func() {
			lem.onGroupConfirmTimeout(groupHash, term, members, zones)
		})
	}
	le.mu.Unlock()

	lgElect.Info("group election: determined winner, broadcasting confirm", "group", groupHash[:8], "winner", winner, "term", term)

	if len(zones) > 0 {
		confirmRecords := map[string][]string{
			"_winner": {string(winner)},
			"_term":   {strconv.FormatUint(term, 10)},
			"_group":  {groupHash},
		}
		if err := lem.broadcastFunc(zones[0], "ELECT-CONFIRM", confirmRecords); err != nil {
			lgElect.Error("failed to broadcast group ELECT-CONFIRM", "group", groupHash[:8], "err", err)
		}
	}
	if complete {
		lem.finalizeGroupElection(groupHash, term, members, zones)
	}
}

func (lem *LeaderElectionManager) onGroupConfirmTimeout(groupHash string, term uint64, members []string, zones []ZoneName) {
	lem.mu.RLock()
	le := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if le == nil {
		return
	}

	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}
	collected := len(le.Confirms)
	expected := le.ExpectedPeers + 1
	if collected < expected {
		le.Active = false
		le.mu.Unlock()
		lgElect.Warn("group election aborted: not all members confirmed, retrying",
			"group", groupHash[:8], "term", term, "confirms", collected, "expected", expected)
		lem.retryGroupElection(le, groupHash, term)
		return
	}
	le.mu.Unlock()
	lem.finalizeGroupElection(groupHash, term, members, zones)
}

func (lem *LeaderElectionManager) finalizeGroupElection(groupHash string, term uint64, members []string, zones []ZoneName) {
	lem.mu.RLock()
	le := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if le == nil {
		return
	}

	le.mu.Lock()
	// Once per term: the last confirm, the own confirm that completes the set
	// and the confirm timer can each get here, and the first one clears Active.
	if le.Term != term || !le.Active {
		le.mu.Unlock()
		return
	}

	var agreedWinner AgentId
	consensus := true
	for _, winner := range le.Confirms {
		if agreedWinner == "" {
			agreedWinner = winner
		} else if winner != agreedWinner {
			consensus = false
			break
		}
	}

	// A winner that is not one of the group's voting members is not taken:
	// the election counts as having found no consensus (the membership
	// design, 4.4).
	if consensus && agreedWinner != "" {
		if voters, known := lem.groupVoters(groupHash, members); known && !isAmong(voters, agreedWinner) {
			lgElect.Warn("election: the winner is not a voting member, not taken",
				"group", shortHash(groupHash), "winner", agreedWinner, "term", term)
			consensus = false
		}
	}

	if !consensus || agreedWinner == "" {
		le.Active = false
		le.mu.Unlock()
		lgElect.Warn("group election: no consensus, re-electing", "group", groupHash[:8], "term", term)
		lem.retryGroupElection(le, groupHash, term)
		return
	}

	lem.noteLeaderLocked(le, agreedWinner, time.Now())
	le.Leader = agreedWinner
	le.leaderTerm = le.Term
	le.LeaderExpiry = time.Now().Add(lem.leaderTTL)
	le.Active = false

	isUs := agreedWinner == lem.localID
	lgElect.Info("group leader elected", "group", groupHash[:8], "leader", agreedWinner, "is_us", isUs, "term", term, "zones", len(zones))
	if isUs {
		le.askedTerm = le.Term // asked below; gossip echoing this term asks nothing more
	}

	lem.scheduleGroupReelection(le, groupHash, members)
	le.mu.Unlock()

	if isUs && lem.onLeaderElected != nil {
		for _, zone := range zones {
			go func(z ZoneName) {
				if err := lem.onLeaderElected(z); err != nil {
					lgElect.Error("onLeaderElected callback failed", "zone", z, "group", groupHash[:8], "error", err)
				}
			}(zone)
		}
	}
}

// scheduleGroupReelection sets up the timer that renews the lease.
//
// One member renews the lease, the leader, at 90% of it. Every other member
// arms a fallback a step later each, in the order of their identities, for a
// leader that has no timer (one that restarted inside its term and learnt
// from gossip that it leads) or whose renewal was lost. A fallback that finds
// the term renewed starts nothing (startGroupElection). When every member
// renewed at the same instant, each started the same term, nobody joined
// anybody, and all aborted after the vote timeout (#120).
//
// members decides only how long this member waits. Whom the renewal calls,
// and through which zone, is read when the timer fires (groupForTimer). Must
// be called with le.mu held.
func (lem *LeaderElectionManager) scheduleGroupReelection(le *LeaderElection, groupHash string, members []string) {
	if le.ReelectTimer != nil {
		le.ReelectTimer.Stop()
	}
	if le.gone {
		return
	}
	armed := le.Term
	delay := lem.renewalDelay(le.Leader, members)
	le.ReelectTimer = time.AfterFunc(delay, func() {
		le.mu.Lock()
		movedOn := le.gone || le.Active || le.Term != armed
		le.mu.Unlock()
		if movedOn {
			lgElect.Debug("group lease already renewed, or an election is running; this renewal does nothing",
				"group", groupHash[:8])
			return
		}
		pg := lem.groupForTimer(groupHash, "lease renewal")
		if pg == nil {
			return
		}
		lgElect.Info("group leader TTL expiring, triggering re-election", "group", groupHash[:8])
		lem.startGroupElection(groupHash, pg.VotingMembers, pg.Zones, &armed)
	})
}

// retryGroupElection starts the election again after one that was aborted or
// found no consensus in term, after a short random delay, and only if no
// other member's retry got there first (startGroupElection). It starts it
// for the group as it is when the delay is over (groupForTimer).
//
// The retry's timer is the election's (RetryTimer), so that a group that goes
// stops it with the others (groupGone). Left running, it fired for a group
// that had gone and come back, found the new election's term-1 entry idle,
// and called a needless term-2 election that could replace the leader just
// elected. A retry that fires as the group goes finds the election gone and
// starts nothing.
func (lem *LeaderElectionManager) retryGroupElection(le *LeaderElection, groupHash string, term uint64) {
	le.mu.Lock()
	defer le.mu.Unlock()
	if le.gone {
		return
	}
	if le.RetryTimer != nil {
		le.RetryTimer.Stop()
	}
	le.RetryTimer = time.AfterFunc(time.Duration(500+rand.Intn(1000))*time.Millisecond, func() {
		le.mu.Lock()
		gone := le.gone
		le.mu.Unlock()
		if gone {
			return
		}
		if pg := lem.groupForTimer(groupHash, "election retry"); pg != nil {
			lem.startGroupElection(groupHash, pg.VotingMembers, pg.Zones, &term)
		}
	})
}

// groupForTimer returns a provider group as the provider group manager has
// it now, for a timer of the group's election that has fired: a lease
// renewal, or the retry after an aborted election. The timer starts its
// election with these voting members and zones, not with the ones the group
// had when the timer was armed, most of a lease earlier: a renewal with the
// old lists was called through a zone that had left the group, and a member
// that elects itself asked for the old zones only (tdns-mp #182).
//
// It returns nil when the timer has nothing to start. The group is gone:
// what is still held for it is dropped. Or this agent has no vote in it (the
// owner took it away, or the agent learnt of the election from gossip), and
// a member without a vote calls no election.
func (lem *LeaderElectionManager) groupForTimer(groupHash, timer string) *ProviderGroup {
	var pg *ProviderGroup
	if lem.providerGroupMgr != nil {
		pg = lem.providerGroupMgr.GetGroup(groupHash)
	}
	if pg == nil {
		lgElect.Info("provider group is gone, its timer starts no election",
			"group", shortHash(groupHash), "timer", timer)
		lem.groupGone(groupHash)
		return nil
	}
	if !isAmong(pg.VotingMembers, lem.localID) {
		lgElect.Info("this agent has no vote in the provider group, its timer starts no election",
			"group", shortHash(groupHash), "timer", timer)
		return nil
	}
	return pg
}

// groupGone is the word that a provider group is gone: its last zone has
// left it (ProviderGroupManager.SetOnGroupGone). The group's election ends
// here: its timers are stopped and its entry is dropped. Kept, the entry
// went on renewing a lease for no zone. Each former member called the
// group's election at the end of its lease, no other member answered (each
// had lost the group too), and the election was aborted and retried without
// an end (tdns-mp #182).
//
// A group that comes back starts from nothing, as a new group does. An
// entry can also come back without the group, through gossip, as for a group
// whose zones are not loaded yet (ApplyGossipElection): it has no timer.
func (lem *LeaderElectionManager) groupGone(groupHash string) {
	lem.mu.Lock()
	le, ok := lem.groupElections[groupHash]
	delete(lem.groupElections, groupHash)
	lem.mu.Unlock()
	if !ok {
		return
	}
	le.mu.Lock()
	le.gone = true
	for _, tm := range []*time.Timer{le.ReelectTimer, le.VoteTimer, le.ConfirmTimer, le.RetryTimer} {
		if tm != nil {
			tm.Stop()
		}
	}
	le.ReelectTimer, le.VoteTimer, le.ConfirmTimer, le.RetryTimer = nil, nil, nil, nil
	leader, term := le.Leader, le.Term
	le.mu.Unlock()
	lgElect.Info("provider group is gone, its election state dropped",
		"group", shortHash(groupHash), "leader", leader, "term", term)
}

// maxRenewalStep is the longest a fallback renewal waits behind the one
// before it.
const maxRenewalStep = 10 * time.Second

// renewalDelay is how long after an election this member waits before it
// renews the lease: the leader 90% of the lease, every other member one step
// more for each member before it in the order of their identities. The steps
// fit in the lease's last tenth, so that the last fallback still fires while
// there is a leader. members is nil for a per-zone election, which does not
// know its members: there every member that is not the leader waits one step.
func (lem *LeaderElectionManager) renewalDelay(leader AgentId, members []string) time.Duration {
	base := lem.leaderTTL * 9 / 10
	if leader == lem.localID {
		return base
	}
	sorted := slices.Clone(members)
	slices.Sort(sorted)
	rank := 1
	for _, m := range sorted {
		if AgentId(m) == lem.localID {
			break
		}
		if AgentId(m) != leader {
			rank++
		}
	}
	step := lem.leaderTTL / 10 / time.Duration(len(members)+2)
	if step > maxRenewalStep {
		step = maxRenewalStep
	}
	return base + time.Duration(rank)*step
}

// GetGroupLeader returns the current leader for a provider group.
func (lem *LeaderElectionManager) GetGroupLeader(groupHash string) (AgentId, bool) {
	lem.mu.RLock()
	le, ok := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if !ok {
		return "", false
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	if le.Leader == "" || time.Now().After(le.LeaderExpiry) {
		return "", false
	}
	return le.Leader, true
}

// InvalidateGroupLeader clears the leader for a group (e.g., when the group degrades).
func (lem *LeaderElectionManager) InvalidateGroupLeader(groupHash string) {
	lem.mu.RLock()
	le, ok := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if !ok {
		return
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	if le.Leader == "" {
		return
	}
	lgElect.Info("invalidating group leader due to degraded state",
		"group", groupHash[:8], "was", le.Leader, "term", le.Term)
	lem.noteLeaderLocked(le, "", time.Now())
	le.Leader = ""
	if le.ReelectTimer != nil {
		le.ReelectTimer.Stop()
		le.ReelectTimer = nil
	}
}

// GetGroupElectionState returns the live election state for a group: the
// term the election is in, and the leader it holds, which while an election
// runs or after an aborted one is still the leader of the term before. It is
// what the status command shows. Outbound gossip does not use it: a peer must
// be told a result only (GroupElectionForGossip).
func (lem *LeaderElectionManager) GetGroupElectionState(groupHash string) GroupElectionState {
	lem.mu.RLock()
	le, ok := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if !ok {
		return GroupElectionState{}
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	return GroupElectionState{
		Leader:       string(le.Leader),
		Term:         uint32(le.Term),
		LeaderExpiry: le.LeaderExpiry,
	}
}

// GroupElectionForGossip returns what this member has to tell its peers of
// the group's election. decided: a term that is decided, with its leader, in
// state. known: the member has an election of its own for the group, decided
// or not.
//
// The live state is not a result at every moment. While an election runs the
// term is already the new one and the leader is not decided: empty in a first
// election, the leader of the term before, with that term's expiry, in a
// renewal. After an aborted election it stays so until the retry. And a member
// that has invalidated its leader has a term without one. A peer stores the
// first record it gets for a term and keeps it for the term, so one of these,
// arriving first, stood for the whole lease (#154). None of them is sent.
//
// A member that is known and not decided tells nothing at all: its caller must
// not pass on a record heard from a peer in its place, which may name the very
// leader this member has invalidated.
func (lem *LeaderElectionManager) GroupElectionForGossip(groupHash string) (state GroupElectionState, decided, known bool) {
	lem.mu.RLock()
	le, ok := lem.groupElections[groupHash]
	lem.mu.RUnlock()
	if !ok {
		return GroupElectionState{}, false, false
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	if le.Term == 0 {
		return GroupElectionState{}, false, false
	}
	if le.Active || le.Leader == "" || le.leaderTerm != le.Term {
		return GroupElectionState{}, false, true
	}
	return GroupElectionState{
		Leader:       string(le.Leader),
		Term:         uint32(le.Term),
		LeaderExpiry: le.LeaderExpiry,
	}, true, true
}

// ApplyGossipElection updates the LEM with election state received via gossip.
func (lem *LeaderElectionManager) ApplyGossipElection(groupHash string, state GroupElectionState) {
	if state.Leader == "" || state.Term == 0 {
		return
	}

	lem.mu.Lock()
	le, ok := lem.groupElections[groupHash]
	if !ok {
		le = &LeaderElection{}
		lem.groupElections[groupHash] = le
	}
	lem.mu.Unlock()

	le.mu.Lock()
	defer le.mu.Unlock()

	if uint64(state.Term) < le.Term {
		return
	}
	news := uint64(state.Term) > le.Term
	if news {
		lgElect.Info("accepted leader from gossip",
			"group", groupHash[:8], "leader", state.Leader,
			"term", state.Term, "expiry", state.LeaderExpiry)

		le.Term = uint64(state.Term)
		lem.noteLeaderLocked(le, AgentId(state.Leader), time.Now())
		le.Leader = AgentId(state.Leader)
		le.leaderTerm = le.Term
		le.LeaderExpiry = state.LeaderExpiry
		le.Active = false
	}

	// An agent that restarts inside its own term learns from its peers that
	// it leads, and no election is held. It asks what an election's winner
	// asks (the SIG(0) key, a delegation sync): the DS set may have changed
	// while it was away, and a sync it had asked for before is gone with
	// the process. The sync sends only a difference, so asking costs
	// nothing when there is none. It asks once per term, for the zones the
	// group has here at that moment. Gossip heard before any zone of the
	// group is loaded finds no group and asks nothing, and no later word of
	// the same term asks either: the gossip table hands a term on once
	// (MergeGossip). Each zone is asked for when it arrives in the group
	// (zoneJoinedGroup). A term this agent won by election has asked
	// already.
	if le.Leader == lem.localID && le.askedTerm != le.Term && lem.onLeaderElected != nil && lem.providerGroupMgr != nil {
		if pg := lem.providerGroupMgr.GetGroup(groupHash); pg != nil {
			le.askedTerm = le.Term
			for _, zone := range pg.Zones {
				go func(z ZoneName) {
					if err := lem.onLeaderElected(z); err != nil {
						lgElect.Error("onLeaderElected callback failed", "zone", z, "group", groupHash[:8], "error", err)
					}
				}(zone)
			}
		}
	}
	if !news {
		return
	}

	// Schedule re-election before leader expires
	if le.ReelectTimer != nil {
		le.ReelectTimer.Stop()
	}
	if lem.providerGroupMgr != nil {
		pg := lem.providerGroupMgr.GetGroup(groupHash)
		if pg != nil {
			if len(pg.VotingMembers) == 0 {
				lgElect.Warn("accepted leader from gossip, but group has no voting members; skipping re-election timer",
					"group", groupHash[:8])
			} else if !isAmong(pg.VotingMembers, lem.localID) {
				// An agent that does not vote renews no lease (the
				// membership design, 4.4).
				lgElect.Debug("accepted leader from gossip; this agent does not vote in the group, and arms no renewal",
					"group", shortHash(groupHash))
			} else {
				lem.scheduleGroupReelection(le, groupHash, pg.VotingMembers)
			}
		}
	}
}

// zoneJoinedGroup is the provider group manager's word that a recompute has
// put a zone into a group: the zone's set of providers changed, or the zone
// is new here. A delegation sync is asked for at an election, for the zones
// the group has then. A zone that arrived in a group whose leader was already
// elected was asked for by nobody, and a change of its delegation waited for
// the next lease renewal. When this agent leads the group, it asks for the
// zone now (onZoneJoined).
//
// What is asked is not what an election's winner is asked (onLeaderElected).
// The zone that arrives has had a leader, and that leader made its SIG(0)
// key, which the parent holds. The winner's key setup makes a key when it
// finds none, and here that would put a new key in place of the one the
// parent trusts. The arrival's callback leaves the key as it is.
//
// A group without a leader asks nothing here: the election that follows asks
// for every zone the group has by then. Nor does a group that another member
// leads: that member is told by its own group manager. The manager tells of
// a zone once, when its group changes, and has the zone in its new group
// before it tells, so the sync that is asked for finds this agent the zone's
// leader.
//
// An election of this agent that is decided in the same instant can ask for
// the zone too. Those are two asks from one agent with one view of the zone,
// and the sync sends only a difference, so the second sends nothing.
//
// Not covered: the agent that led the group the zone left. It stops acting
// for the zone when its own refresh moves the zone, and until then it reads
// itself as the zone's leader. A lease renewal of its group in that time asks
// for a sync from the view it still has, and a difference computed from that
// view undoes what was sent from here; the parent keeps what arrives last.
// Nothing in this function can see that agent's view. A leader that acts only
// when the views of a zone agree is what closes it (the membership design).
func (lem *LeaderElectionManager) zoneJoinedGroup(zone ZoneName, from, to string) {
	if lem.onZoneJoined == nil {
		return
	}
	if leader, ok := lem.GetGroupLeader(to); !ok || leader != lem.localID {
		return
	}
	// Since step 8 every zone of a group has the group's voting members,
	// so a group's elected leader votes in each of them. A leader record
	// that names this agent for a group it does not vote in (one taken as
	// an observer, or a stale one) does not make it take a zone up: it does
	// not lead that zone (IsLeader). Kept as that guard.
	if !votesInZone(zone, lem.localID) {
		lgElect.Info("zone joined a group this agent leads, but this agent does not vote in the zone: it does not take the zone up",
			"zone", zone, "group", shortHash(to))
		return
	}
	was := "no group"
	if from != "" {
		was = shortHash(from)
	}
	lgElect.Info("zone joined a group this agent leads, asking for its delegation sync",
		"zone", zone, "group", shortHash(to), "was_in", was)
	go func() {
		if err := lem.onZoneJoined(zone); err != nil {
			lgElect.Error("onZoneJoined callback failed", "zone", zone, "group", shortHash(to), "error", err)
		}
	}()
}

// electAtFirstLoad is the zone's election at its first load, for a zone
// whose delegation sync is the agents'. It runs after the parentsync
// detection. With no voting peer counted it elects (startElection leaves a
// zone that a group covers to the group); a zone in a group is the group's;
// otherwise the election waits for the peers to become OPERATIONAL.
func (lem *LeaderElectionManager) electAtFirstLoad(zd *tdns.ZoneData) {
	if !zd.Options[tdns.OptParentSync] {
		return
	}
	zone := ZoneName(zd.ZoneName)
	// A zone with an HSYNC3 RRset is checked by zoneChanged, from its first
	// load's post-refresh, after the groups are recomputed (step 8). One
	// with parentsync and no HSYNC3 RRset is no multi-provider zone, and
	// elects here as before.
	if hasHSYNC3(zoneApex(zone)) {
		return
	}
	configured := lem.configuredPeers(zone)
	if configured == 0 {
		lem.StartElection(zone, 0)
		return
	}
	if lem.providerGroupMgr != nil {
		if pg := lem.providerGroupMgr.GetGroupForZone(zone); pg != nil {
			lem.leaveElectionToGroup(pg.GroupHash)
			return
		}
	}
	lem.DeferElection(zone)
}

// zoneChanged is the one check of a zone's election (step 8, design 4.5),
// at the zone's first load and at every change of its HSYNC3 or HSYNCPARAM
// RRset, after the groups are recomputed. For a zone with an HSYNC3 RRset
// and parentsync on:
//
//  1. this agent does not vote in the zone: nothing is started, and the
//     zone's own election, if it holds one, is dropped;
//  2. a group covers the zone: the zone's own election is dropped, and
//     nothing else is done; the group's election decides;
//  3. no group covers the zone and this agent is its only voting member:
//     it elects itself, unless it leads already (#149).
func (lem *LeaderElectionManager) zoneChanged(zone ZoneName) {
	if !votesInZone(zone, lem.localID) {
		lem.dropZoneElection(zone)
		return
	}
	if lem.providerGroupMgr != nil {
		if pg := lem.providerGroupMgr.GetGroupForZone(zone); pg != nil {
			lem.dropZoneElection(zone)
			return
		}
	}
	if lem.configuredPeers(zone) == 0 && !lem.IsLeader(zone) {
		lem.StartElection(zone, 0)
	}
}

// dropZoneElection drops the zone's own election, its timers and a deferred
// election: a group covers the zone now, or this agent does not vote in it.
func (lem *LeaderElectionManager) dropZoneElection(zone ZoneName) {
	lem.mu.Lock()
	le, ok := lem.elections[zone]
	delete(lem.elections, zone)
	delete(lem.pendingElections, zone)
	lem.mu.Unlock()
	if !ok {
		return
	}
	le.mu.Lock()
	le.gone = true
	for _, tm := range []*time.Timer{le.ReelectTimer, le.VoteTimer, le.ConfirmTimer, le.RetryTimer} {
		if tm != nil {
			tm.Stop()
		}
	}
	le.ReelectTimer, le.VoteTimer, le.ConfirmTimer, le.RetryTimer = nil, nil, nil, nil
	leader, term := le.Leader, le.Term
	le.mu.Unlock()
	lgElect.Info("the zone's own election is dropped: a group covers the zone, or this agent does not vote in it",
		"zone", zone, "leader", leader, "term", term)
}

// DeferElection records a zone as needing an election once peers become operational.
func (lem *LeaderElectionManager) DeferElection(zone ZoneName) {
	lem.mu.Lock()
	lem.pendingElections[zone] = true
	lem.mu.Unlock()
	lgElect.Info("deferring leader election until peers are operational", "zone", zone)
}

// NotifyPeerOperational is called when a peer becomes operational.
func (lem *LeaderElectionManager) NotifyPeerOperational(peerZones []ZoneName) {
	var candidates []ZoneName

	lem.mu.RLock()
	for _, zone := range peerZones {
		if lem.pendingElections[zone] {
			candidates = append(candidates, zone)
			continue
		}
		if le, ok := lem.elections[zone]; ok {
			le.mu.Lock()
			needsElection := le.Leader == "" || time.Now().After(le.LeaderExpiry)
			le.mu.Unlock()
			if needsElection {
				candidates = append(candidates, zone)
			}
		}
	}
	lem.mu.RUnlock()

	if len(candidates) == 0 {
		return
	}

	for _, zone := range candidates {
		configured := lem.configuredPeers(zone)
		if configured == 0 {
			continue
		}

		// Route to group election if provider group exists
		if lem.providerGroupMgr != nil {
			pg := lem.providerGroupMgr.GetGroupForZone(zone)
			if pg != nil {
				lem.mu.Lock()
				delete(lem.pendingElections, zone)
				lem.mu.Unlock()
				lem.leaveElectionToGroup(pg.GroupHash)
				continue
			}
		}

		// No provider group — per-zone election
		operational := 0
		if lem.operationalPeersFunc != nil {
			operational = lem.operationalPeersFunc(zone)
		}
		if operational >= configured {
			lgElect.Info("all configured peers operational, starting per-zone election",
				"zone", zone, "operational", operational, "configured", configured)
			lem.mu.Lock()
			delete(lem.pendingElections, zone)
			lem.mu.Unlock()
			lem.StartElection(zone, configured)
		} else if operational > 0 {
			lgElect.Debug("waiting for all configured peers before election",
				"zone", zone, "operational", operational, "configured", configured)
		}
	}
}

// GetPendingElections returns zones with deferred elections (waiting for peers).
func (lem *LeaderElectionManager) GetPendingElections() []ZoneName {
	lem.mu.RLock()
	defer lem.mu.RUnlock()
	result := make([]ZoneName, 0, len(lem.pendingElections))
	for zone := range lem.pendingElections {
		result = append(result, zone)
	}
	return result
}

// getOrCreate returns the election state for a zone, creating if needed.
func (lem *LeaderElectionManager) getOrCreate(zone ZoneName) *LeaderElection {
	lem.mu.Lock()
	defer lem.mu.Unlock()
	le, ok := lem.elections[zone]
	if !ok {
		le = &LeaderElection{
			Zone:     zone,
			Votes:    make(map[AgentId]uint32),
			Confirms: make(map[AgentId]AgentId),
		}
		lem.elections[zone] = le
	}
	return le
}

// GetLeader returns the current leader for a zone, if known and not expired.
func (lem *LeaderElectionManager) GetLeader(zone ZoneName) (AgentId, bool) {
	lem.mu.RLock()
	le, ok := lem.elections[zone]
	lem.mu.RUnlock()
	if !ok {
		return "", false
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	if le.Leader == "" || time.Now().After(le.LeaderExpiry) {
		return "", false
	}
	return le.Leader, true
}

// noteLeaderLocked keeps le.leadStart, one above the term in which this
// agent's present lead began, as an election names its leader (under le.mu,
// with le.Term the new term). A renewal names this agent again while its
// lease runs, and keeps the start; a lead after another agent's, an
// invalidated or a lapsed one starts anew; another agent's lead clears it.
// One above, so that a lead at term 0 is a lead.
func (lem *LeaderElectionManager) noteLeaderLocked(le *LeaderElection, leader AgentId, now time.Time) {
	if leader != lem.localID {
		le.leadStart = 0
		return
	}
	if le.Leader != lem.localID || le.leadStart == 0 || now.After(le.LeaderExpiry) {
		le.leadStart = le.Term + 1
	}
}

// LeadStart names this agent's present lead of the zone (one above the term
// it began in), as IsLeader finds the zone's election: its provider group's,
// else the zone's own. Zero when it does not lead the zone.
func (lem *LeaderElectionManager) LeadStart(zone ZoneName) uint64 {
	if !lem.IsLeader(zone) {
		return 0
	}
	lem.mu.RLock()
	le, ok := (*LeaderElection)(nil), false
	if lem.providerGroupMgr != nil {
		if pg := lem.providerGroupMgr.GetGroupForZone(zone); pg != nil {
			le, ok = lem.groupElections[pg.GroupHash]
		}
	}
	if !ok {
		le, ok = lem.elections[zone]
	}
	lem.mu.RUnlock()
	if !ok || le == nil {
		return 0
	}
	le.mu.Lock()
	defer le.mu.Unlock()
	return le.leadStart
}

// IsLeader returns true if the local agent is the current leader for a zone.
//
// An agent that does not vote in a multi-provider zone does not lead it,
// whatever lease it holds (decision 34; the membership design, 2.2): a lead
// from before its roles were taken no longer counts. A zone with no HSYNC3
// RRset is left as it is.
func (lem *LeaderElectionManager) IsLeader(zone ZoneName) bool {
	if !votesInZone(zone, lem.localID) {
		return false
	}
	// Check group-based leader first
	if lem.providerGroupMgr != nil {
		pg := lem.providerGroupMgr.GetGroupForZone(zone)
		if pg != nil {
			leader, ok := lem.GetGroupLeader(pg.GroupHash)
			if ok {
				return leader == lem.localID
			}
		}
	}
	// Fall back to per-zone election
	leader, ok := lem.GetLeader(zone)
	if !ok {
		return false
	}
	return leader == lem.localID
}

// ZoneLeader returns the agent this agent knows as the zone's current
// leader, the way IsLeader decides it: the leader of the zone's provider
// group if there is one, else the zone's own.
func (lem *LeaderElectionManager) ZoneLeader(zone ZoneName) (AgentId, bool) {
	if lem.providerGroupMgr != nil {
		if pg := lem.providerGroupMgr.GetGroupForZone(zone); pg != nil {
			if leader, ok := lem.GetGroupLeader(pg.GroupHash); ok {
				return leader, true
			}
		}
	}
	return lem.GetLeader(zone)
}

// GetAllLeaders returns the current leader status for all zones with an active leader.
//
// IsSelf is this agent's lead as IsLeader has it: a lease held in a zone
// this agent does not vote in is no lead of its own (decision 34). That is
// asked once the election locks are free, as IsLeader asks it.
func (lem *LeaderElectionManager) GetAllLeaders() []LeaderStatus {
	result := lem.allLeases()
	for i := range result {
		if result[i].IsSelf && !votesInZone(result[i].Zone, lem.localID) {
			result[i].IsSelf = false
		}
	}
	return result
}

// allLeases is GetAllLeaders by the leases alone.
func (lem *LeaderElectionManager) allLeases() []LeaderStatus {
	lem.mu.RLock()
	defer lem.mu.RUnlock()

	groupCoveredZones := make(map[ZoneName]bool)

	var result []LeaderStatus

	// Group-based leaders first
	for groupHash, le := range lem.groupElections {
		le.mu.Lock()
		if le.Leader != "" && time.Now().Before(le.LeaderExpiry) {
			var zones []ZoneName
			if lem.providerGroupMgr != nil {
				pg := lem.providerGroupMgr.GetGroup(groupHash)
				if pg != nil {
					zones = pg.Zones
				}
			}
			for _, zone := range zones {
				groupCoveredZones[zone] = true
				result = append(result, LeaderStatus{
					Zone:   zone,
					Leader: le.Leader,
					IsSelf: le.Leader == lem.localID,
					Term:   le.Term,
					Expiry: le.LeaderExpiry,
				})
			}
		}
		le.mu.Unlock()
	}

	// Per-zone leaders (only for zones not covered by group elections)
	for zone, le := range lem.elections {
		if groupCoveredZones[zone] {
			continue
		}
		le.mu.Lock()
		if le.Leader != "" && time.Now().Before(le.LeaderExpiry) {
			result = append(result, LeaderStatus{
				Zone:   zone,
				Leader: le.Leader,
				IsSelf: le.Leader == lem.localID,
				Term:   le.Term,
				Expiry: le.LeaderExpiry,
			})
		}
		le.mu.Unlock()
	}
	return result
}

// StartElection initiates a new election for a zone.
func (lem *LeaderElectionManager) StartElection(zone ZoneName, expectedPeers int) {
	lem.startElection(zone, expectedPeers, nil)
}

// startElection is StartElection, for a timer when armed is set, as
// startGroupElection is for a group: it starts nothing when the zone's
// election has moved on since the timer was armed.
//
// Only a voting member of the zone starts an election, whatever asks for it:
// the first load, a lease renewal, the retry after no consensus, a peer that
// becomes OPERATIONAL, the operator (the membership design, 4.4). A zone with
// no HSYNC3 RRset is not a multi-provider zone and elects as before.
//
// A count of zero self-elects only where no group covers the zone. A zero
// count meant a single participant while auditors were counted. It no longer
// does: a group of one voting member and an auditor is covered by its group's
// election, which decides.
func (lem *LeaderElectionManager) startElection(zone ZoneName, expectedPeers int, armed *uint64) {
	if !votesInZone(zone, lem.localID) {
		lgElect.Debug("no election started: this agent does not vote in the zone", "zone", zone)
		return
	}
	if lem.providerGroupMgr != nil {
		pg := lem.providerGroupMgr.GetGroupForZone(zone)
		if pg != nil {
			lgElect.Debug("skipping per-zone election, zone covered by provider group",
				"zone", zone, "group", pg.GroupHash[:8])
			return
		}
	}

	le := lem.getOrCreate(zone)
	le.mu.Lock()

	if armed != nil && (le.Active || le.Term != *armed) {
		term := le.Term
		le.mu.Unlock()
		lgElect.Debug("election has moved on since this timer was armed, starting none",
			"zone", zone, "armed", *armed, "term", term)
		return
	}

	// Single agent: become leader immediately
	if expectedPeers == 0 {
		lem.noteLeaderLocked(le, lem.localID, time.Now())
		le.Leader = lem.localID
		le.leaderTerm = le.Term
		le.LeaderExpiry = time.Now().Add(lem.leaderTTL)
		le.Active = false
		lgElect.Info("single agent, self-elected as leader", "zone", zone)
		lem.scheduleReelection(le)
		le.mu.Unlock()

		if lem.onLeaderElected != nil {
			go func() {
				if err := lem.onLeaderElected(zone); err != nil {
					lgElect.Error("onLeaderElected callback failed", "zone", zone, "error", err)
				}
			}()
		}
		return
	}

	// Reset election state
	le.Active = true
	le.Term++
	le.MyVote = rand.Uint32()
	le.Votes = map[AgentId]uint32{lem.localID: le.MyVote}
	le.Confirms = make(map[AgentId]AgentId)
	le.ExpectedPeers = expectedPeers
	term := le.Term
	le.takeEarlyVotes(term, false)
	vote := le.MyVote

	if le.VoteTimer != nil {
		le.VoteTimer.Stop()
	}
	if le.ConfirmTimer != nil {
		le.ConfirmTimer.Stop()
	}

	le.VoteTimer = time.AfterFunc(5*time.Second, func() {
		lem.onVoteTimeout(zone, term)
	})

	le.mu.Unlock()

	lgElect.Info("starting election", "zone", zone, "term", term, "peers", expectedPeers)

	records := map[string][]string{
		"_term": {strconv.FormatUint(term, 10)},
	}
	if err := lem.broadcastFunc(zone, "ELECT-CALL", records); err != nil {
		lgElect.Error("failed to broadcast ELECT-CALL", "zone", zone, "err", err)
	}

	voteRecords := map[string][]string{
		"_vote": {strconv.FormatUint(uint64(vote), 10)},
		"_term": {strconv.FormatUint(term, 10)},
	}
	if err := lem.broadcastFunc(zone, "ELECT-VOTE", voteRecords); err != nil {
		lgElect.Error("failed to broadcast ELECT-VOTE", "zone", zone, "err", err)
	}
}

// HandleMessage dispatches an incoming election message to the appropriate handler.
func (lem *LeaderElectionManager) HandleMessage(zone ZoneName, senderID AgentId, rfiType string, records map[string][]string) {
	if lem.providerGroupMgr != nil {
		pg := lem.providerGroupMgr.GetGroupForZone(zone)
		if pg != nil {
			lgElect.Debug("ignoring per-zone election message, zone covered by provider group",
				"zone", zone, "type", rfiType, "group", pg.GroupHash[:8])
			return
		}
	}

	// A CALL, a VOTE or a CONFIRM counts only from a voting member of the
	// zone, and only a voting member takes part, as in HandleGroupMessage. A
	// zone this agent does not know, or that has no HSYNC3 RRset, has no
	// standings, and is not checked (votesInZone).
	if !votesInZone(zone, senderID) {
		lgElect.Warn("election: message from a sender that is not a voting member of the zone, dropped",
			"zone", zone, "type", rfiType, "sender", senderID, "term", parseUint64(records, "_term"))
		return
	}
	if !votesInZone(zone, lem.localID) {
		lgElect.Info("leader election observed (not a voting member, no participation)",
			"zone", zone, "type", rfiType, "initiator", senderID, "term", parseUint64(records, "_term"))
		return
	}

	switch rfiType {
	case "ELECT-CALL":
		lem.handleCall(zone, senderID, records)
	case "ELECT-VOTE":
		lem.handleVote(zone, senderID, records)
	case "ELECT-CONFIRM":
		lem.handleConfirm(zone, senderID, records)
	}
}

func (lem *LeaderElectionManager) handleCall(zone ZoneName, senderID AgentId, records map[string][]string) {
	term := parseUint64(records, "_term")
	le := lem.getOrCreate(zone)
	le.mu.Lock()

	if le.Active && le.Term >= term {
		ourTerm := le.Term
		le.mu.Unlock()
		lgElect.Debug("ignoring ELECT-CALL with stale term", "zone", zone, "our_term", ourTerm, "their_term", term)
		return
	}

	le.Active = true
	le.Term = term
	le.MyVote = rand.Uint32()
	le.Votes = map[AgentId]uint32{lem.localID: le.MyVote}
	le.Confirms = make(map[AgentId]AgentId)
	// A member that joins counts against the zone's configured peers, as one
	// that calls does. The count used to be set by a call of one's own only:
	// a member that had only ever joined counted against no peers, and
	// settled on the first vote or confirm it received (#129).
	le.ExpectedPeers = lem.configuredPeers(zone)
	// A vote for this term that got here before the CALL (keepEarlyVote).
	// With it the votes can be complete already, which handleVote would have
	// seen had the vote come after the CALL.
	le.takeEarlyVotes(term, true)
	allVotes := len(le.Votes) > 1 && len(le.Votes) >= le.ExpectedPeers+1
	vote := le.MyVote

	if le.VoteTimer != nil {
		le.VoteTimer.Stop()
	}
	if !allVotes {
		le.VoteTimer = time.AfterFunc(5*time.Second, func() {
			lem.onVoteTimeout(zone, term)
		})
	}

	le.mu.Unlock()

	lgElect.Info("joining election", "zone", zone, "term", term, "from", senderID)

	voteRecords := map[string][]string{
		"_vote": {strconv.FormatUint(uint64(vote), 10)},
		"_term": {strconv.FormatUint(term, 10)},
	}
	if err := lem.broadcastFunc(zone, "ELECT-VOTE", voteRecords); err != nil {
		lgElect.Error("failed to broadcast ELECT-VOTE", "zone", zone, "err", err)
	}

	if allVotes {
		go lem.determineAndConfirm(zone, term)
	}
}

func (lem *LeaderElectionManager) handleVote(zone ZoneName, senderID AgentId, records map[string][]string) {
	term := parseUint64(records, "_term")
	vote := uint32(parseUint64(records, "_vote"))

	le := lem.getOrCreate(zone)
	le.mu.Lock()
	defer le.mu.Unlock()

	if !le.Active || le.Term != term {
		if le.keepEarlyVote(term, senderID, vote) {
			lgElect.Debug("vote for a term not joined yet, kept for its CALL", "zone", zone, "from", senderID, "term", term, "our_term", le.Term)
		} else {
			lgElect.Debug("ignoring vote for wrong term", "zone", zone, "expected", le.Term, "got", term)
		}
		return
	}

	le.Votes[senderID] = vote
	lgElect.Info("received vote", "zone", zone, "from", senderID, "vote", vote, "votes_collected", len(le.Votes), "expected", le.ExpectedPeers+1)

	if len(le.Votes) >= le.ExpectedPeers+1 {
		if le.VoteTimer != nil {
			le.VoteTimer.Stop()
		}
		go lem.determineAndConfirm(zone, term)
	}
}

func (lem *LeaderElectionManager) handleConfirm(zone ZoneName, senderID AgentId, records map[string][]string) {
	term := parseUint64(records, "_term")
	winner := AgentId(parseString(records, "_winner"))

	le := lem.getOrCreate(zone)
	le.mu.Lock()

	if !le.Active || le.Term != term {
		active, ourTerm := le.Active, le.Term
		le.mu.Unlock()
		lgElect.Debug("ignoring confirm for inactive/wrong term", "zone", zone, "active", active, "expected", ourTerm, "got", term)
		return
	}

	le.Confirms[senderID] = winner
	lgElect.Info("received confirm", "zone", zone, "from", senderID, "winner", winner, "confirms_collected", len(le.Confirms), "expected", le.ExpectedPeers+1)

	if len(le.Confirms) >= le.ExpectedPeers+1 {
		if le.ConfirmTimer != nil {
			le.ConfirmTimer.Stop()
		}
		le.mu.Unlock()
		lem.finalizeElection(zone, term)
		return
	}

	le.mu.Unlock()
}

func (lem *LeaderElectionManager) onVoteTimeout(zone ZoneName, term uint64) {
	le := lem.getOrCreate(zone)
	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}

	collected := len(le.Votes)
	expected := le.ExpectedPeers + 1
	if collected < expected {
		le.Active = false
		le.mu.Unlock()
		lgElect.Warn("election aborted: not all peers voted, cannot elect without full participation",
			"zone", zone, "term", term, "votes", collected, "expected", expected)
		return
	}
	le.mu.Unlock()

	lem.determineAndConfirm(zone, term)
}

func (lem *LeaderElectionManager) determineAndConfirm(zone ZoneName, term uint64) {
	le := lem.getOrCreate(zone)
	le.mu.Lock()

	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}

	winner := determineWinner(le.Votes)
	le.Confirms[lem.localID] = winner
	// As in determineAndConfirmGroup: the peers' confirms may be in already,
	// and ours then completes the set.
	complete := len(le.Confirms) >= le.ExpectedPeers+1

	if le.ConfirmTimer != nil {
		le.ConfirmTimer.Stop()
	}
	if !complete {
		le.ConfirmTimer = time.AfterFunc(5*time.Second, func() {
			lem.onConfirmTimeout(zone, term)
		})
	}

	le.mu.Unlock()

	lgElect.Info("determined winner, broadcasting confirm", "zone", zone, "winner", winner, "term", term)

	confirmRecords := map[string][]string{
		"_winner": {string(winner)},
		"_term":   {strconv.FormatUint(term, 10)},
	}
	if err := lem.broadcastFunc(zone, "ELECT-CONFIRM", confirmRecords); err != nil {
		lgElect.Error("failed to broadcast ELECT-CONFIRM", "zone", zone, "err", err)
	}
	if complete {
		lem.finalizeElection(zone, term)
	}
}

func (lem *LeaderElectionManager) onConfirmTimeout(zone ZoneName, term uint64) {
	le := lem.getOrCreate(zone)
	le.mu.Lock()
	if !le.Active || le.Term != term {
		le.mu.Unlock()
		return
	}

	collected := len(le.Confirms)
	expected := le.ExpectedPeers + 1
	if collected < expected {
		le.Active = false
		le.mu.Unlock()
		lgElect.Warn("election aborted: not all peers confirmed, cannot elect without full participation",
			"zone", zone, "term", term, "confirms", collected, "expected", expected)
		return
	}
	le.mu.Unlock()

	lem.finalizeElection(zone, term)
}

func (lem *LeaderElectionManager) finalizeElection(zone ZoneName, term uint64) {
	le := lem.getOrCreate(zone)
	le.mu.Lock()

	// Once per term, as finalizeGroupElection.
	if le.Term != term || !le.Active {
		le.mu.Unlock()
		return
	}

	var agreedWinner AgentId
	consensus := true
	for _, winner := range le.Confirms {
		if agreedWinner == "" {
			agreedWinner = winner
		} else if winner != agreedWinner {
			consensus = false
			break
		}
	}

	// A winner that is not a voting member of the zone is not taken: the
	// election counts as having found no consensus.
	if consensus && agreedWinner != "" && !votesInZone(zone, agreedWinner) {
		lgElect.Warn("election: the winner is not a voting member, not taken",
			"zone", zone, "winner", agreedWinner, "term", term)
		consensus = false
	}

	if !consensus || agreedWinner == "" {
		le.Active = false
		expectedPeers := le.ExpectedPeers
		le.mu.Unlock()
		lgElect.Warn("no consensus, re-electing", "zone", zone, "term", term)
		// Re-elect after a short random delay, unless another member's
		// retry got there first.
		time.AfterFunc(time.Duration(500+rand.Intn(1000))*time.Millisecond, func() {
			lem.startElection(zone, expectedPeers, &term)
		})
		return
	}

	lem.noteLeaderLocked(le, agreedWinner, time.Now())
	le.Leader = agreedWinner
	le.leaderTerm = le.Term
	le.LeaderExpiry = time.Now().Add(lem.leaderTTL)
	le.Active = false

	isUs := agreedWinner == lem.localID
	lgElect.Info("leader elected", "zone", zone, "leader", agreedWinner, "is_us", isUs, "term", term, "ttl", lem.leaderTTL)

	lem.scheduleReelection(le)
	le.mu.Unlock()

	// If we won, trigger delegation sync setup (SIG(0) key generation + bootstrap)
	if isUs && lem.onLeaderElected != nil {
		go func() {
			if err := lem.onLeaderElected(zone); err != nil {
				lgElect.Error("onLeaderElected callback failed", "zone", zone, "error", err)
			}
		}()
	}
}

// scheduleReelection sets up the timer that renews the lease: the leader at
// 90% of it, every other member a step later as a fallback, and each only
// while the election still stands in the term the timer was armed in
// (scheduleGroupReelection has the reasons). Must be called with le.mu held.
func (lem *LeaderElectionManager) scheduleReelection(le *LeaderElection) {
	if le.ReelectTimer != nil {
		le.ReelectTimer.Stop()
	}
	zone := le.Zone
	armed := le.Term
	le.ReelectTimer = time.AfterFunc(lem.renewalDelay(le.Leader, nil), func() {
		le.mu.Lock()
		movedOn := le.gone || le.Active || le.Term != armed
		le.mu.Unlock()
		if movedOn {
			lgElect.Debug("lease already renewed, or an election is running; this renewal does nothing", "zone", zone)
			return
		}

		configured := lem.configuredPeers(zone)

		if configured == 0 {
			lgElect.Info("leader TTL expiring, single agent, re-self-electing", "zone", zone)
			lem.startElection(zone, 0, &armed)
			return
		}

		if lem.providerGroupMgr != nil {
			pg := lem.providerGroupMgr.GetGroupForZone(zone)
			if pg != nil {
				lgElect.Info("leader TTL expiring, deferring to group re-election",
					"zone", zone, "group", pg.GroupHash[:8])
				lem.leaveElectionToGroup(pg.GroupHash)
				return
			}
		}

		operational := 0
		if lem.operationalPeersFunc != nil {
			operational = lem.operationalPeersFunc(zone)
		}
		if operational >= configured {
			lgElect.Info("leader TTL expiring, all peers operational, triggering re-election",
				"zone", zone, "operational", operational, "configured", configured)
			lem.startElection(zone, configured, &armed)
		} else {
			lgElect.Warn("leader TTL expiring, not all configured peers operational — no election, change freeze",
				"zone", zone, "operational", operational, "configured", configured)
			lem.DeferElection(zone)
		}
	})
}

// keepEarlyVote keeps a vote that arrived for a term newer than the one this
// member is in. A member joins a term on the CALL, and the CALL and another
// member's VOTE come from different senders, with nothing to order them: a
// VOTE that got here first used to be dropped, the member then never held
// every vote, and the election waited out the 5 s timeout and ran again
// (#125). Only the newest such term is kept, one vote per sender. A vote for a
// term at or below the current one is late, and dropped as before.
//
// A CONFIRM needs no such care: a member confirms only once it holds every
// vote, this member's among them, and this member votes when it joins.
//
// It reports whether it kept the vote. Must be called with le.mu held.
func (le *LeaderElection) keepEarlyVote(term uint64, sender AgentId, vote uint32) bool {
	if term <= le.Term || term < le.earlyTerm {
		return false
	}
	if term > le.earlyTerm || le.earlyVotes == nil {
		le.earlyTerm = term
		le.earlyVotes = make(map[AgentId]uint32)
	}
	le.earlyVotes[sender] = vote
	return true
}

// takeEarlyVotes adds the votes kept for the term this member has just joined
// to its votes, and forgets what was kept for this term or an older one. A
// member that starts a term of its own calls it with apply false: what was
// kept belongs to an election that start replaces. Must be called with le.mu
// held, after Votes has been reset for the term.
func (le *LeaderElection) takeEarlyVotes(term uint64, apply bool) {
	if apply && le.earlyTerm == term {
		for id, vote := range le.earlyVotes {
			le.Votes[id] = vote
		}
	}
	if le.earlyTerm <= term {
		le.earlyTerm, le.earlyVotes = 0, nil
	}
}

// determineWinner picks the agent with the highest vote. Ties broken by lexicographic label.
func determineWinner(votes map[AgentId]uint32) AgentId {
	var winner AgentId
	var highVote uint32
	for id, vote := range votes {
		if vote > highVote || (vote == highVote && string(id) < string(winner)) {
			winner = id
			highVote = vote
		}
	}
	return winner
}

// activeSig0KeyIDs lists the key ids of keyName's active SIG(0) keys: all of
// them, where GetSig0Keys keeps one.
func activeSig0KeyIDs(hdb *HsyncDB, keyName string) (map[uint16]bool, error) {
	resp, err := hdb.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "list"})
	if err != nil {
		return nil, err
	}
	ids := map[uint16]bool{}
	for mapkey, k := range resp.Sig0keys {
		if !strings.EqualFold(dns.Fqdn(k.Name), dns.Fqdn(keyName)) || k.State != tdns.Sig0StateActive {
			continue
		}
		_, idstr, ok := strings.Cut(mapkey, "::")
		if !ok {
			continue
		}
		if id, err := strconv.ParseUint(idstr, 10, 16); err == nil {
			ids[uint16(id)] = true
		}
	}
	return ids, nil
}

// dropKeyMadeForALostLead deletes a SIG(0) key the leader's setup made, when
// the lead moved before the setup could publish it. Left active, the key
// would be handed to the next leader that asks this agent, and published the
// next time this agent leads, though the parent never saw it. A key this
// agent already held, or imported from a peer, is the group's and stays. Nor is a key deleted that is
// not the zone's only active key: the delete cannot be undone, and the one
// the parent trusts may be the other.
func dropKeyMadeForALostLead(hdb *HsyncDB, zone, keyName string, keyid uint16) {
	if ids, err := activeSig0KeyIDs(hdb, keyName); err != nil || len(ids) != 1 || !ids[keyid] {
		lgAgent.Warn("onLeaderElected: the SIG(0) key made for a lead that has moved is kept: it is not the zone's only active key, or the keys could not be listed",
			"zone", zone, "keyid", keyid, "active", len(ids), "err", err)
		return
	}
	if _, err := hdb.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "delete",
		Zone: zone, Keyname: keyName, Keyid: keyid}); err != nil {
		lgAgent.Error("onLeaderElected: the SIG(0) key made for a lead that has moved could not be deleted; it stays active",
			"zone", zone, "keyid", keyid, "err", err)
		return
	}
	lgAgent.Info("onLeaderElected: the SIG(0) key made for a lead that has moved is deleted", "zone", zone, "keyid", keyid)
}

// importSig0KeyFromPeer imports a SIG(0) key received from a peer via RFI CONFIG.
// TODO: This calls unexported tdns functions (PrepareKeyCache, Sig0KeyMgmt).
// It will need to be reworked when those are exported or moved.
func importSig0KeyFromPeer(hdb *HsyncDB, keyName string, configData map[string]string) error {
	algorithm := configData["algorithm"]
	privatekey := configData["privatekey"]
	keyrr := configData["keyrr"]

	if algorithm == "" || privatekey == "" || keyrr == "" {
		return fmt.Errorf("incomplete key data: algorithm=%q privatekey=%d bytes keyrr=%q",
			algorithm, len(privatekey), keyrr)
	}

	// Parse the PEM private key + KEY RR into a PrivateKeyCache
	pkc, err := tdns.PrepareKeyCache(privatekey, keyrr)
	if err != nil {
		return fmt.Errorf("PrepareKeyCache failed: %v", err)
	}

	// The keystore files the key under its KEY RR's owner, so a key for
	// another name must not be added in keyName's place.
	if pkc.KeyType != dns.TypeKEY || dns.CanonicalName(pkc.KeyRR.Hdr.Name) != dns.CanonicalName(keyName) {
		return fmt.Errorf("peer sent a key for %q, not a KEY for %q", pkc.KeyRR.Hdr.Name, keyName)
	}
	// A zone that publishes a KEY takes only that key: one the zone does not
	// publish would put a key the parent does not know in place of the one
	// it trusts. The peers asked include agents with no role any more
	// (roleLessKeyHolders), whose keystore need not hold the zone's key.
	if !zoneTakesKey(ZoneName(keyName), &pkc.KeyRR) {
		return fmt.Errorf("peer sent key %d, which %s does not publish", pkc.KeyRR.KeyTag(), keyName)
	}

	// Nor a private key that is not the KEY's own half: it would be stored
	// active, and its signatures would not validate against the published
	// KEY. Same check as tdns's bulk SIG(0) import.
	if _, err := tdns.VerifyStoredKeyPair(pkc.PrivateKeyPEM, &pkc.KeyRR.DNSKEY); err != nil {
		return fmt.Errorf("peer's private key for %q does not match its KEY: %v", keyName, err)
	}

	// Import via Sig0KeyMgmt "add" (also adds to TrustStore)
	kp := tdns.KeystorePost{
		Command:         "sig0-mgmt",
		SubCommand:      "add",
		Keyname:         keyName,
		State:           tdns.Sig0StateActive,
		PrivateKeyCache: pkc,
	}
	resp, err := sig0KeyMgmtRetried(hdb.KeyDB, kp)
	if err != nil {
		return fmt.Errorf("Sig0KeyMgmt add failed: %v", err)
	}
	if resp.Error {
		return fmt.Errorf("Sig0KeyMgmt add error: %s", resp.ErrorMsg)
	}
	lgElect.Info("imported SIG(0) key from peer", "name", keyName, "algorithm", algorithm, "keyid", pkc.KeyId)
	// One active key per zone (step 7b): with the key added, every other
	// active key is retired, so that a failed import never leaves the agent
	// without one. A retire that fails leaves the zone's key not held; it is
	// tried again at the next check of the key.
	if zk, err := readZoneKey(hdb.KeyDB, ZoneName(keyName)); err == nil && zk.held != nil && zk.held.keyid == pkc.KeyId {
		if only, err := retireOtherActiveKeys(hdb.KeyDB, ZoneName(keyName), zk); err != nil || !only {
			lgElect.Warn("the imported SIG(0) key is not yet the zone's only active key", "zone", keyName, "keyid", pkc.KeyId, "err", err)
		}
	}
	return nil
}

// broadcastElectToZone sends an election RFI message to the zone's voting
// members and its auditors (the plan's 3.2), by an explicit test: Agents
// holds the role holders today, and every member from the switch on.
func (ar *AgentRegistry) broadcastElectToZone(zone ZoneName, rfiType string, records map[string][]string) error {
	zad, err := ar.GetZoneAgentData(zone)
	if err != nil {
		return fmt.Errorf("broadcastElectToZone: %w", err)
	}

	for _, agent := range electRecipients(zone, zad.Agents, AgentId(ar.LocalAgent.Identity)) {
		if !ar.isAgentOperational(agent.ID) {
			lgElect.Debug("skipping non-operational agent", "agent", agent.ID)
			continue
		}
		msg := &AgentMsgPost{
			MessageType:  AgentMsgRfi,
			OriginatorID: AgentId(ar.LocalAgent.Identity),
			Zone:         zone,
			RfiType:      rfiType,
			Records:      records,
			Time:         time.Now(),
		}
		go func(a *Agent) {
			if _, err := ar.sendRfiToAgent(a, msg); err != nil {
				lgElect.Warn("failed to send election message", "agent", a.ID, "rfiType", rfiType, "err", err)
			}
		}(agent)
	}
	return nil
}

// electRecipients are the agents an election message goes to: the zone's
// voting members and its auditors, other than self.
func electRecipients(zone ZoneName, agents []*Agent, self AgentId) []*Agent {
	apex := zoneApex(zone)
	var out []*Agent
	for _, agent := range agents {
		if isAmong([]string{string(agent.ID)}, self) {
			continue
		}
		if st := zoneStanding(apex, string(agent.ID)); st == standingVoting || st == standingAuditor {
			out = append(out, agent)
		}
	}
	return out
}

// Helper functions for parsing records

func parseUint64(records map[string][]string, key string) uint64 {
	vals, ok := records[key]
	if !ok || len(vals) == 0 {
		return 0
	}
	v, _ := strconv.ParseUint(vals[0], 10, 64)
	return v
}

func parseString(records map[string][]string, key string) string {
	vals, ok := records[key]
	if !ok || len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// Sig0KeyOwnerName computes the RFC 9615-style owner name for a child SIG(0) KEY RR.
// Format: _sig0key.<zone>._signal.<nameserver>
func Sig0KeyOwnerName(zone, nameserver string) string {
	return "_sig0key." + dns.Fqdn(zone) + "_signal." + dns.Fqdn(nameserver)
}

// GetParentSyncStatus computes the current parent sync status for a zone on demand.
func (lem *LeaderElectionManager) GetParentSyncStatus(zone ZoneName, zd *tdns.ZoneData, hdb *HsyncDB, imr *Imr, ar *AgentRegistry, schemes []string) ParentSyncStatus {
	status := ParentSyncStatus{
		Zone:        zone,
		LastChecked: time.Now(),
	}

	// 1. Leader election state — check group-based election first
	groupFound := false
	if lem.providerGroupMgr != nil {
		pg := lem.providerGroupMgr.GetGroupForZone(zone)
		if pg != nil {
			lem.mu.RLock()
			le, ok := lem.groupElections[pg.GroupHash]
			lem.mu.RUnlock()
			if ok {
				le.mu.Lock()
				status.Leader = le.Leader
				status.LeaderExpiry = le.LeaderExpiry
				status.ElectionTerm = le.Term
				le.mu.Unlock()
				groupFound = true
			}
		}
	}
	if !groupFound {
		le := lem.getOrCreate(zone)
		le.mu.Lock()
		status.Leader = le.Leader
		status.LeaderExpiry = le.LeaderExpiry
		status.ElectionTerm = le.Term
		le.mu.Unlock()
	}
	// The same test as IsLeader: a lead that no longer counts is not shown
	// as this agent's.
	status.IsLeader = status.Leader == lem.localID && time.Now().Before(status.LeaderExpiry) && votesInZone(zone, lem.localID)

	// The zone's catch-up (catchup.go), which needs neither the zone's data
	// nor the keystore.
	if ar != nil && ar.MPTransport != nil {
		t := ar.MPTransport.catchUp
		status.CatchUp = t.Status(zone)
		if owed, room := t.owedState(zone); owed && status.IsLeader {
			caughtUp, _ := t.CaughtUp(zone)
			switch {
			case !caughtUp:
				status.ParentSync = "held until the zone is caught up"
			case room:
				status.ParentSync = "owed, the delegation sync queue is full"
			default:
				status.ParentSync = "owed"
			}
		}
	}

	if zd == nil || hdb == nil {
		return status
	}

	// 2. SIG(0) key info
	targetName := tdns.DsyncUpdateTargetName(string(zone))
	if targetName == "" {
		targetName = string(zone)
	}
	sak, err := hdb.GetSig0Keys(targetName, tdns.Sig0StateActive)
	if err == nil && len(sak.Keys) > 0 {
		key := sak.Keys[0]
		status.KeyAlgorithm = dns.AlgorithmToString[key.Algorithm]
		status.KeyID = key.KeyId
		status.KeyRR = key.KeyRR.String()

		// Read parent_state from keystore
		var parentState int
		row := hdb.DB.QueryRow("SELECT COALESCE(parent_state, 0) FROM Sig0KeyStore WHERE zonename=? AND keyid=?",
			targetName, key.KeyId)
		if err := row.Scan(&parentState); err == nil {
			status.ParentState = uint8(parentState)
			status.ParentStateName = edns0.KeyStateToString(uint8(parentState))
		}
	}

	// 3. Check apex records
	owner, err := zd.GetOwner(zd.ZoneName)
	if err == nil && owner != nil {
		if keys, keyExists := owner.RRtypes.Get(dns.TypeKEY); keyExists {
			status.ApexPublished = true
			status.ApexKeys = len(keys.RRs)
		}
		if cdsRRset, exists := owner.RRtypes.Get(dns.TypeCDS); exists && len(cdsRRset.RRs) > 0 {
			status.CdsPublished = true
		}
		if csyncRRset, exists := owner.RRtypes.Get(dns.TypeCSYNC); exists && len(csyncRRset.RRs) > 0 {
			status.CsyncPublished = true
		}
		status.ZoneSigned = zd.Options[tdns.OptOnlineSigning] || zd.Options[tdns.OptInlineSigning]
	}

	// 4. Get child NS names
	if owner != nil {
		nsRRset := owner.RRtypes.GetOnlyRRSet(dns.TypeNS)
		for _, rr := range nsRRset.RRs {
			if nsRR, ok := rr.(*dns.NS); ok {
				status.ChildNS = append(status.ChildNS, nsRR.Ns)
			}
		}
	}

	// 5. Check _signal KEY publication for each child NS via IMR.
	if imr != nil && imr.Imr != nil && len(status.ChildNS) > 0 && status.KeyAlgorithm != "" {
		status.KeyPublication = make(map[string]bool)
		for _, ns := range status.ChildNS {
			ownerName := Sig0KeyOwnerName(string(zone), ns)
			resp, err := imr.ImrQuery(context.Background(), ownerName, dns.TypeKEY, dns.ClassINET, nil)
			published := err == nil && resp != nil && resp.RRset != nil && len(resp.RRset.RRs) > 0
			status.KeyPublication[ownerName] = published
		}
	}

	// 6. DSYNC discovery — find what sync schemes the parent supports
	if imr != nil && imr.Imr != nil {
		dsyncRes, err := imr.DsyncDiscovery(context.Background(), string(zone), false)
		if err == nil {
			status.ParentZone = dsyncRes.Parent
			for _, drr := range dsyncRes.Rdata {
				scheme := "UNKNOWN"
				switch drr.Scheme {
				case core.SchemeNotify:
					scheme = "NOTIFY"
				case core.SchemeUpdate:
					scheme = "UPDATE"
				case core.SchemeScanner:
					scheme = "SCANNER"
				case core.SchemeAPI:
					scheme = "API"
				}
				rrtype := dns.TypeToString[drr.Type]
				if rrtype == "" {
					rrtype = fmt.Sprintf("TYPE%d", drr.Type)
				}
				status.SyncSchemes = append(status.SyncSchemes, DsyncSchemeInfo{
					Scheme: scheme,
					Type:   rrtype,
					Target: drr.Target,
					Port:   drr.Port,
				})
			}
			status.ActiveScheme = pickActiveSyncScheme(schemes, dsyncRes.Rdata)
		}
	}

	// 7. Peer agents for this zone
	if ar != nil {
		zad, err := ar.GetZoneAgentData(zone)
		if err == nil {
			for _, agent := range zad.Agents {
				if agent.ID == lem.localID {
					continue // skip self
				}
				// Which transport is live reads the canonical transport.Peer
				// per-mechanism state (END.0, decayed); was {Dns,Api}Details.State.
				transportStr := "-"
				if ar.TransportManager != nil {
					if peer, ok := ar.TransportManager.PeerRegistry.Get(string(agent.ID)); ok {
						if st, ok := peer.MechanismEffectiveState("DNS"); ok && st == transport.PeerStateOperational {
							transportStr = "DNS"
						} else if st, ok := peer.MechanismEffectiveState("API"); ok && st == transport.PeerStateOperational {
							transportStr = "API"
						}
					}
				}
				// The state goes out by its name. A value the table does not
				// hold goes out by its number, not as an empty string.
				state := ar.effectiveAgentState(agent.ID)
				stateName, ok := AgentStateToString[state]
				if !ok {
					stateName = fmt.Sprintf("STATE%d", state)
				}
				status.Peers = append(status.Peers, PeerSyncInfo{
					Identity:    agent.ID,
					State:       stateName,
					Transport:   transportStr,
					Operational: ar.isAgentOperational(agent.ID),
				})
			}
		}
	}

	return status
}

// PublishKeyToCombiner sends a KEY RR to the combiner as a REPLACE operation.
func PublishKeyToCombiner(zone ZoneName, keyRR dns.RR, tm *MPTransportBridge) (string, error) {
	update := &ZoneUpdate{
		Zone: zone,
		Operations: []core.RROperation{{
			Operation: "replace",
			RRtype:    "KEY",
			Records:   []string{keyRR.String()},
		}},
	}
	return tm.EnqueueForCombiner(zone, update, "")
}

// pickActiveSyncScheme returns the first configured child scheme, in
// preference order, that the parent advertises through DSYNC, or "" when
// none matches. It mirrors the selection walk of tdns's former
// ZoneData.BestSyncScheme, which tdns 6fd0a688 removed as dead code on the
// tdns side; the parentsync status report is its remaining consumer.
func pickActiveSyncScheme(schemes []string, rdata []*core.DSYNC) string {
	for _, scheme := range schemes {
		switch strings.ToLower(scheme) {
		case "update":
			for _, drr := range rdata {
				if drr.Scheme == core.SchemeUpdate {
					return "UPDATE"
				}
			}
		case "notify":
			for _, drr := range rdata {
				if drr.Scheme == core.SchemeNotify && (drr.Type == dns.TypeCSYNC || drr.Type == dns.TypeANY) {
					return "NOTIFY"
				}
			}
		case "api":
			for _, drr := range rdata {
				if drr.Scheme == core.SchemeAPI {
					return "API"
				}
			}
		}
	}
	return ""
}
