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
		elections:             make(map[ZoneName]*LeaderElection),
		pendingElections:      make(map[ZoneName]bool),
		groupElections:        make(map[string]*LeaderElection),
		pendingGroupElections: make(map[string]bool),
		localID:               localID,
		leaderTTL:             leaderTTL,
		broadcastFunc:         broadcastFunc,
	}
}

// SetProviderGroupManager sets the provider group manager for group-based elections.
func (lem *LeaderElectionManager) SetProviderGroupManager(pgm *ProviderGroupManager) {
	lem.providerGroupMgr = pgm
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

// SetOnLeaderElected sets the callback invoked when the local agent wins an election.
func (lem *LeaderElectionManager) SetOnLeaderElected(f func(zone ZoneName) error) {
	lem.onLeaderElected = f
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
	delete(lem.pendingGroupElections, groupHash)
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
		le.Leader = lem.localID
		le.leaderTerm = le.Term
		le.LeaderExpiry = time.Now().Add(lem.leaderTTL)
		le.Active = false
		lgElect.Info("single agent in group, self-elected as leader", "group", groupHash[:8])
		lem.scheduleGroupReelection(le, groupHash, members, zones)
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

// DeferGroupElection records a group as needing an election when OnGroupOperational fires.
func (lem *LeaderElectionManager) DeferGroupElection(groupHash string) {
	lem.mu.Lock()
	lem.pendingGroupElections[groupHash] = true
	lem.mu.Unlock()
	lgElect.Info("deferring group election until group is operational", "group", groupHash[:8])
}

// isAmong: whether id is one of a group's voting members. Names are compared
// as FQDNs, as the authorization of a sender is: the members come from zone
// data and carry the trailing dot, an identity from a config or a message
// need not. One comparison for the sender and for this agent itself: with two,
// an agent whose configured identity lacked the dot was counted by its peers
// and took itself for an observer.
func isAmong(members []string, id AgentId) bool {
	return slices.ContainsFunc(members, func(m string) bool { return dns.Fqdn(m) == dns.Fqdn(string(id)) })
}

// HandleGroupMessage dispatches an election message that carries a _group record.
func (lem *LeaderElectionManager) HandleGroupMessage(groupHash string, senderID AgentId, rfiType string, records map[string][]string) {
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
		lem.retryGroupElection(groupHash, term, members, zones)
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
		lem.retryGroupElection(groupHash, term, members, zones)
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

	if !consensus || agreedWinner == "" {
		le.Active = false
		le.mu.Unlock()
		lgElect.Warn("group election: no consensus, re-electing", "group", groupHash[:8], "term", term)
		lem.retryGroupElection(groupHash, term, members, zones)
		return
	}

	le.Leader = agreedWinner
	le.leaderTerm = le.Term
	le.LeaderExpiry = time.Now().Add(lem.leaderTTL)
	le.Active = false

	isUs := agreedWinner == lem.localID
	lgElect.Info("group leader elected", "group", groupHash[:8], "leader", agreedWinner, "is_us", isUs, "term", term, "zones", len(zones))
	if isUs {
		le.askedTerm = le.Term // asked below; gossip echoing this term asks nothing more
	}

	lem.scheduleGroupReelection(le, groupHash, members, zones)
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
// anybody, and all aborted after the vote timeout (#120). Must be called
// with le.mu held.
func (lem *LeaderElectionManager) scheduleGroupReelection(le *LeaderElection, groupHash string, members []string, zones []ZoneName) {
	if le.ReelectTimer != nil {
		le.ReelectTimer.Stop()
	}
	armed := le.Term
	delay := lem.renewalDelay(le.Leader, members)
	le.ReelectTimer = time.AfterFunc(delay, func() {
		le.mu.Lock()
		movedOn := le.Active || le.Term != armed
		le.mu.Unlock()
		if movedOn {
			lgElect.Debug("group lease already renewed, or an election is running; this renewal does nothing",
				"group", groupHash[:8])
			return
		}
		lgElect.Info("group leader TTL expiring, triggering re-election", "group", groupHash[:8])
		lem.startGroupElection(groupHash, members, zones, &armed)
	})
}

// retryGroupElection starts the election again after one that was aborted or
// found no consensus in term, after a short random delay, and only if no
// other member's retry got there first (startGroupElection).
func (lem *LeaderElectionManager) retryGroupElection(groupHash string, term uint64, members []string, zones []ZoneName) {
	time.AfterFunc(time.Duration(500+rand.Intn(1000))*time.Millisecond, func() {
		lem.startGroupElection(groupHash, members, zones, &term)
	})
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

		le.Leader = AgentId(state.Leader)
		le.Term = uint64(state.Term)
		le.leaderTerm = le.Term
		le.LeaderExpiry = state.LeaderExpiry
		le.Active = false
	}

	// An agent that restarts inside its own term learns from its peers that
	// it leads, and no election is held. It asks what an election's winner
	// asks (the SIG(0) key, a delegation sync): the DS set may have changed
	// while it was away, and a sync it had asked for before is gone with
	// the process. The sync sends only a difference, so asking costs
	// nothing when there is none. It asks once per term, and only once the
	// group is known: gossip heard before this agent's groups are
	// registered asks nothing yet, and the same term's next word asks then.
	// A term this agent won by election has asked already.
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
			} else {
				lem.scheduleGroupReelection(le, groupHash, pg.VotingMembers, pg.Zones)
			}
		}
	}
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
				lem.DeferGroupElection(pg.GroupHash)
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

// IsLeader returns true if the local agent is the current leader for a zone.
func (lem *LeaderElectionManager) IsLeader(zone ZoneName) bool {
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
func (lem *LeaderElectionManager) GetAllLeaders() []LeaderStatus {
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
func (lem *LeaderElectionManager) startElection(zone ZoneName, expectedPeers int, armed *uint64) {
	if expectedPeers > 0 && lem.providerGroupMgr != nil {
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
		movedOn := le.Active || le.Term != armed
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
				lem.DeferGroupElection(pg.GroupHash)
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

	// Import via Sig0KeyMgmt "add" (also adds to TrustStore)
	kp := tdns.KeystorePost{
		Command:         "sig0-mgmt",
		SubCommand:      "add",
		Keyname:         keyName,
		State:           tdns.Sig0StateActive,
		PrivateKeyCache: pkc,
	}
	resp, err := hdb.Sig0KeyMgmt(nil, kp)
	if err != nil {
		return fmt.Errorf("Sig0KeyMgmt add failed: %v", err)
	}
	if resp.Error {
		return fmt.Errorf("Sig0KeyMgmt add error: %s", resp.ErrorMsg)
	}
	lgElect.Info("imported SIG(0) key from peer", "name", keyName, "algorithm", algorithm, "keyid", pkc.KeyId)
	return nil
}

// broadcastElectToZone sends an election RFI message to all agents in a zone.
func (ar *AgentRegistry) broadcastElectToZone(zone ZoneName, rfiType string, records map[string][]string) error {
	zad, err := ar.GetZoneAgentData(zone)
	if err != nil {
		return fmt.Errorf("broadcastElectToZone: %w", err)
	}

	for _, agent := range zad.Agents {
		if AgentId(agent.ID) == AgentId(ar.LocalAgent.Identity) {
			continue // don't send to ourselves
		}
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
	status.IsLeader = status.Leader == lem.localID && time.Now().Before(status.LeaderExpiry)

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
		if _, keyExists := owner.RRtypes.Get(dns.TypeKEY); keyExists {
			status.ApexPublished = true
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
