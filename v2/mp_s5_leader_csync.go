/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The zone's CSYNC (tdns-mp #175). A parent that is told of an NS change by
 * NOTIFY(CSYNC) scans the zone's nameservers and compares what they serve,
 * the CSYNC included. Each signing provider's combiner used to make its own
 * CSYNC, so two signers served two, and nothing told the leader when the
 * providers served any.
 *
 * Now the zone has one, and the leader makes it: parent communication is
 * the leader's, and the CSYNC is part of it. A change of the NS set reaches
 * every provider as a SYNC; the leader is one of them, and its delegation
 * analysis then finds the zone differing from the parent. It makes a CSYNC
 * and sends it to every provider the way a provider's NS records go: as a
 * contribution, by SYNC, to the other agents and to its own combiner. Each
 * agent hands it to its combiner and confirms. When every confirmation is
 * in, the zone's wait begins (mp_s5_leader_sync.go), and then the
 * NOTIFY(CSYNC) leaves.
 *
 * A receiving agent takes a CSYNC from the zone's leader and from nobody
 * else.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// csyncFlagImmediate is the CSYNC flag that lets the parent act on the
// record when it has read it (RFC 7477 section 3.2.1). tdns's parent acts
// on no CSYNC without it. The flag came and went before (tdns-mp #151): with
// a NOTIFY that left before the nameservers served the change, it made the
// parent apply the state from before the change. The NOTIFY now waits.
// soaminimum is not set: the serial field is not a zone serial.
const csyncFlagImmediate = 0x0001

// delegationCsyncAwaitedEvery is how often the leader says that a NOTIFY
// still waits for confirmations of the zone's CSYNC. There is no time-out:
// a provider that does not confirm does not serve the record, and a parent
// that scans then finds the nameservers out of step.
var delegationCsyncAwaitedEvery = 10 * time.Minute

// delegationCsyncSubmitTimeout bounds how long the syncher waits for the
// agent's data engine to take the CSYNC and say whether it could be queued
// for the providers.
var delegationCsyncSubmitTimeout = 5 * time.Second

// delegationCsync is the CSYNC this agent made, as the leader, for a zone.
type delegationCsync struct {
	diff      string    // the difference of NS set and glue it was made for (delegationNSDifference)
	record    string    // the record, as it was sent
	distID    string    // the distribution it went out with, once the data engine has said
	serial    uint32    // its serial field
	made      time.Time // when it was made
	confirmed bool      // every recipient has given its final confirmation
	failed    error     // a recipient rejected it, and no NOTIFY waited for it then
	awaited   []string  // the recipients whose final confirmation is missing
}

// delegationCsyncStep comes before a sync of a zone this agent leads goes to
// the parent. If the zone's NS set or glue differs from the parent's, the
// zone is signed, and no CSYNC has been made for this difference, it makes
// one and sends it to the zone's providers. It does not wait for them: an
// UPDATE goes to the parent at once, with the CSYNC distributed beside it,
// and a NOTIFY waits in the chain.
//
// A sync that finds the difference the CSYNC was made for makes none: an
// election asks for a sync at every renewal of the lease, and an operator
// may ask at any time. Nor do the chain's own checks of the parent: nothing
// has changed since the CSYNC they follow.
//
// Reported is an error if the CSYNC could not be handed over for
// distribution; a NOTIFY(CSYNC) must then not leave.
func (conf *Config) delegationCsyncStep(ctx context.Context, zone string, syncstate tdns.DelegationSyncStatus) error {
	nsdiff := delegationNSDifference(syncstate)
	if nsdiff == "" {
		return nil
	}
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return nil
	}
	// The zone is signed if a provider signs it: what the combiner asked
	// when it made the CSYNC. An unsigned zone has none.
	if hp := mpzd.getHSYNCPARAM(); hp == nil || len(hp.GetSigners()) == 0 {
		return nil
	}
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	ch := c.zones[zone]
	// the chain's own check, as delegationSyncNotifiedWith tells it
	own := ch != nil && !ch.waiting && ch.notified != ""
	cur := c.csyncs[zone]
	if own && cur != nil {
		// A check may find another difference than the one the CSYNC was
		// made for: the parent has taken part of the change. The zone has
		// not changed, so the CSYNC stands for what is left, and the next
		// election does not find a difference to make a new one for.
		cur.diff = nsdiff
	}
	c.mu.Unlock()
	if own || (cur != nil && cur.diff == nsdiff && cur.failed == nil) {
		return nil
	}

	// The serial field orders the CSYNC records of a zone at every
	// combiner: the newest is served. The time is what makes a later one
	// newer. Two leaders' clocks can disagree, and a new leader's record
	// must not be discarded as the older one, so it is also made newer
	// than every CSYNC this agent knows of for the zone.
	serial := uint32(time.Now().Unix())
	if known, ok := conf.newestKnownCsyncSerial(mpzd, cur); ok && !serialNewer(serial, known) {
		serial = known + 1
	}
	csync := &dns.CSYNC{
		Hdr:        dns.RR_Header{Name: mpzd.ZoneName, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: 120},
		Serial:     serial,
		Flags:      csyncFlagImmediate,
		TypeBitMap: []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA},
	}
	why := "the zone's NS set or glue differs from the parent's"
	if cur != nil {
		why = "the difference between the zone's NS set or glue and the parent's has changed"
	}
	made := &delegationCsync{diff: nsdiff, record: csync.String(), serial: serial, made: time.Now()}
	if tm := conf.InternalMp.MPTransport; tm != nil {
		made.awaited = tm.GetDistributionRecipients(ZoneName(zone), false)
		sort.Strings(made.awaited)
	}
	// remembered before it is handed over: the data engine reports on it
	// from its own goroutine (delegationCsyncProgress)
	c.mu.Lock()
	if c.csyncs == nil {
		c.csyncs = map[string]*delegationCsync{}
	}
	c.csyncs[zone] = made
	c.mu.Unlock()
	if err := conf.distributeCsync(ctx, zone, csync); err != nil {
		c.mu.Lock()
		if c.csyncs[zone] == made {
			delete(c.csyncs, zone)
		}
		c.mu.Unlock()
		lgEngine.Error("the zone's CSYNC could not be handed over for distribution", "zone", zone, "serial", serial, "err", err)
		return fmt.Errorf("the zone's CSYNC could not be distributed: %w", err)
	}
	lgEngine.Info("made a CSYNC for the zone and sent it to the zone's providers", "zone", zone, "serial", serial, "why", why)
	return nil
}

// newestKnownCsyncSerial is the newest serial field among the CSYNC records
// this agent knows of for the zone: the one it made last, those the agents
// have contributed (its data repo holds every agent's), and the one in its
// copy of the zone.
func (conf *Config) newestKnownCsyncSerial(mpzd *MPZoneData, cur *delegationCsync) (newest uint32, known bool) {
	note := func(serial uint32) {
		if !known || serialNewer(serial, newest) {
			newest, known = serial, true
		}
	}
	noteAll := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if csync, ok := rr.(*dns.CSYNC); ok {
				note(csync.Serial)
			}
		}
	}
	if cur != nil {
		note(cur.serial)
	}
	if zdr := conf.InternalMp.ZoneDataRepo; zdr != nil {
		if repo, ok := zdr.Get(ZoneName(mpzd.ZoneName)); ok {
			for _, od := range repo.Data.Items() {
				if od == nil {
					continue
				}
				if rrset, ok := od.RRtypes.Get(dns.TypeCSYNC); ok {
					noteAll(rrset.RRs)
				}
			}
		}
	}
	if apex, err := mpzd.GetOwner(mpzd.ZoneName); err == nil && apex != nil {
		if rrset, ok := apex.RRtypes.Get(dns.TypeCSYNC); ok {
			noteAll(rrset.RRs)
		}
	}
	return newest, known
}

// distributeCsync hands the CSYNC to the agent's data engine as this
// agent's own contribution: a REPLACE of its CSYNC, which the engine sends
// to the agent's combiner and to every other agent of the zone through the
// reliable queue, and whose confirmations it tracks, as for an NS record.
func (conf *Config) distributeCsync(ctx context.Context, zone string, csync *dns.CSYNC) error {
	msgQs := conf.InternalMp.MsgQs
	if msgQs == nil || msgQs.SynchedDataUpdate == nil {
		return fmt.Errorf("the agent's data engine is not running")
	}
	us := AgentId(conf.MpConfig().Identity)
	answer := make(chan *AgentMsgResponse, 1)
	update := &SynchedDataUpdate{
		Zone:       ZoneName(zone),
		AgentId:    us,
		UpdateType: "local",
		Update: &ZoneUpdate{
			Zone:    ZoneName(zone),
			AgentId: us,
			RRsets:  map[uint16]core.RRset{},
			Operations: []core.RROperation{{
				Operation: "replace",
				RRtype:    dns.TypeToString[dns.TypeCSYNC],
				Records:   []string{csync.String()},
			}},
		},
		Response: answer,
	}
	var stopped <-chan struct{}
	if ctx != nil {
		stopped = ctx.Done()
	}
	timeout := time.NewTimer(delegationCsyncSubmitTimeout)
	defer timeout.Stop()
	select {
	case msgQs.SynchedDataUpdate <- update:
	case <-stopped:
		return ctx.Err()
	case <-timeout.C:
		return fmt.Errorf("the agent's data engine did not take the CSYNC within %s", delegationCsyncSubmitTimeout)
	}
	select {
	case resp := <-answer:
		if resp != nil && resp.Error {
			return fmt.Errorf("%s", resp.ErrorMsg)
		}
		return nil
	case <-stopped:
		return ctx.Err()
	case <-timeout.C:
		return fmt.Errorf("the agent's data engine did not answer for the CSYNC within %s", delegationCsyncSubmitTimeout)
	}
}

// delegationCsyncProgress is called by the agent's data engine, from its own
// goroutine, when it has distributed a local update of a zone and when it
// has processed a confirmation for one. It reads how far the zone's CSYNC
// has come from what the engine tracks for every record it distributes: who
// must confirm (the agent's combiner and every other agent of the zone) and
// who has, with what answer. An agent's final confirmation is its
// combiner's word, so it says that the provider holds the record.
//
// Every recipient has confirmed: a NOTIFY that waited for this is held for
// the zone's wait from now, and then leaves. A recipient has rejected the
// record: the sync has failed; a NOTIFY that waited is dropped, the failure
// chain asks again, and that ask makes and distributes a new CSYNC.
//
// detail is the confirmation just processed, nil after a local update. A
// recipient's final word that it failed or refuses, with nothing said of
// the record (its zone is not there, it could not process the message), is
// booked for no record by the engine; it is a rejection all the same, and
// that recipient will not be heard again.
func (conf *Config) delegationCsyncProgress(ctx context.Context, zdr *ZoneDataRepo, zonename ZoneName, detail *ConfirmationDetail) {
	zone := string(zonename)
	c := &conf.InternalMp.delegationSyncChains
	c.mu.Lock()
	cur := c.csyncs[zone]
	if cur == nil || cur.confirmed || cur.failed != nil {
		c.mu.Unlock()
		return
	}
	record, distID := cur.record, cur.distID
	c.mu.Unlock()

	tr := zdr.trackedRR(zonename, AgentId(conf.MpConfig().Identity), dns.TypeCSYNC, record)
	if tr == nil {
		return
	}
	var awaited []string
	var rejectedBy, reason string
	for _, r := range tr.ExpectedRecipients {
		switch got := tr.Confirmations[r]; got.Status {
		case "", "pending":
			awaited = append(awaited, r)
		case "rejected":
			rejectedBy, reason = r, got.Reason
		}
	}
	sort.Strings(awaited)
	if detail != nil && detail.DistributionID == tr.DistributionID && (detail.Status == "FAILED" || detail.Status == "REJECTED") &&
		rejectedBy == "" && slices.Contains(awaited, detail.Source) {
		rejectedBy, reason = detail.Source, "its final confirmation was "+detail.Status+" and named no record"
		if detail.Message != "" {
			reason = detail.Message
		}
	}
	rejected := tr.State == RRStateRejected || rejectedBy != ""
	if rejected && rejectedBy == "" {
		rejectedBy, reason = "a provider", tr.Reason
	}
	if !rejected && distID != "" && tr.DistributionID != distID {
		// An operator's resync has sent the record again, to the combiner
		// alone and under a new distribution: the engine now tracks that
		// one, and what the other providers answer to the first is not
		// booked. Whether they all hold the record is not known any more.
		rejected, rejectedBy = true, "this agent's resync"
		reason = "the record was sent again before every provider had confirmed it, and their confirmations are lost"
	}

	c.mu.Lock()
	if c.csyncs[zone] != cur {
		c.mu.Unlock()
		return
	}
	if cur.distID == "" {
		cur.distID = tr.DistributionID
	}
	ch := c.zones[zone]
	waited := ch != nil && ch.hold != nil && ch.hold.awaiting
	switch {
	case rejected:
		cause := fmt.Errorf("the zone's CSYNC was rejected by %s: %s", rejectedBy, reason)
		var dropped string
		if waited {
			dropped = notifyTypes(ch.hold.notifies)
			ch.hold, ch.waiting = nil, false
			delete(c.csyncs, zone)
		} else {
			// no NOTIFY waits for it (yet): the sync that hands one over
			// finds this, and fails
			cur.failed = cause
		}
		c.mu.Unlock()
		lgEngine.Warn("the zone's CSYNC was rejected", "zone", zone, "serial", cur.serial, "by", rejectedBy, "reason", reason)
		if waited {
			lgEngine.Info("the NOTIFY that waited for the zone's CSYNC is dropped: the CSYNC was rejected", "zone", zone, "notify", dropped)
			conf.delegationSyncFailed(ctx, zone, cause)
		}
	case len(awaited) == 0:
		cur.confirmed, cur.awaited = true, nil
		took := time.Since(cur.made).Round(time.Millisecond)
		var hold *delegationNotifyHold
		var ask int
		if waited {
			hold = ch.hold
			hold.awaiting = false
			ch.failures = 0
			ask = c.schedule(ch)
		}
		c.mu.Unlock()
		lgEngine.Info("every provider has confirmed the zone's CSYNC", "zone", zone, "serial", cur.serial, "took", took)
		if hold != nil {
			// the zone's wait, counted from the last confirmation
			sent := delegationNotifies{out: hold.out}
			sent.wait, sent.largest = conf.delegationNotifyWait(zone)
			if sent.wait > 0 {
				lgEngine.Info("a NOTIFY to the parent is held until the zone's nameservers have had time to serve the change", "zone", zone, "notify", notifyTypes(hold.notifies), "wait", sent.wait, "largest", sent.largest)
			}
			conf.delegationSyncReleaseAfter(ctx, zone, ask, sent, hold.delays)
		}
	default:
		cur.awaited = awaited
		c.mu.Unlock()
	}
}

// trackedRR is what the data engine tracks for one record an agent
// contributes to a zone. Called from the engine's goroutine, which owns the
// tracking.
func (zdr *ZoneDataRepo) trackedRR(zone ZoneName, agent AgentId, rrtype uint16, record string) *TrackedRR {
	if zdr == nil || zdr.Tracking[zone] == nil || zdr.Tracking[zone][agent] == nil {
		return nil
	}
	tracked := zdr.Tracking[zone][agent][rrtype]
	if tracked == nil {
		return nil
	}
	for i := range tracked.Tracked {
		if tracked.Tracked[i].RR.String() == record {
			return &tracked.Tracked[i]
		}
	}
	return nil
}

// delegationCsyncAwaitedAfter says, after a while and then again, that a
// NOTIFY still waits for confirmations of the zone's CSYNC, and from whom.
// It ends with the hold it speaks of. An agent that has lost the leadership
// meanwhile drops what it holds.
func (conf *Config) delegationCsyncAwaitedAfter(ctx context.Context, zone string, ask int, every time.Duration) {
	c := &conf.InternalMp.delegationSyncChains
	time.AfterFunc(every, func() {
		stopped := ctx != nil && ctx.Err() != nil
		leads := conf.leadsZone(zone)
		c.mu.Lock()
		ch, cur := c.zones[zone], c.csyncs[zone]
		if ch == nil || ch.ask != ask || ch.hold == nil || !ch.hold.awaiting || cur == nil {
			c.mu.Unlock()
			return
		}
		if stopped || !leads {
			c.mu.Unlock()
			conf.delegationSyncNotLeading(zone, stopped)
			return
		}
		types, awaited, waited := notifyTypes(ch.hold.notifies), slices.Clone(cur.awaited), time.Since(cur.made).Round(time.Second)
		c.mu.Unlock()
		lgEngine.Info("the NOTIFY to the parent still waits for the providers' confirmations of the zone's CSYNC", "zone", zone, "notify", types, "serial", cur.serial, "awaited", awaited, "waited", waited)
		conf.delegationCsyncAwaitedAfter(ctx, zone, ask, every)
	})
}

// refuseCsyncNotFromLeader takes the CSYNC operations out of an update that
// another agent sent, unless that agent is the one this agent knows as the
// zone's delegation sync leader. The zone has one CSYNC, the leader's; a
// CSYNC from anybody else, or while no leader is known, is rejected, and
// the sender is told so in a final confirmation. The rest of the update is
// processed as usual. Returned is the reason, empty if nothing was refused.
//
// The sender is the one the transport established, never the one the update
// names: on the DNS mechanism the identity whose key opened the message. The
// agent the update says it comes from must be the same. An update that
// carries no transport sender has no sender for this rule, and its CSYNC is
// rejected. (On the HTTPS mechanism the transport's sender is still the one
// the message names, checked only to be a known peer: tdns-mp #56.)
func (conf *Config) refuseCsyncNotFromLeader(u *SynchedDataUpdate, msgQs *MsgQs) string {
	if u == nil || u.Update == nil {
		return ""
	}
	csync := dns.TypeToString[dns.TypeCSYNC]
	if !slices.ContainsFunc(u.Update.Operations, func(op core.RROperation) bool { return strings.EqualFold(op.RRtype, csync) }) {
		return ""
	}
	sender := u.DeliveredBy
	var leader AgentId
	known := false
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		leader, known = lem.ZoneLeader(u.Zone)
	}
	same := func(a, b AgentId) bool { return dns.CanonicalName(string(a)) == dns.CanonicalName(string(b)) }
	if known && same(sender, leader) && same(u.AgentId, leader) {
		return ""
	}
	senderName := string(sender)
	if senderName == "" {
		senderName = "(not established)"
	}
	reason := fmt.Sprintf("a CSYNC is taken only from the zone's delegation sync leader: the sender is %s, the leader is %s", senderName, leader)
	leaderName := string(leader)
	if !known {
		reason = fmt.Sprintf("a CSYNC is taken only from the zone's delegation sync leader: the sender is %s, and no leader is known", senderName)
		leaderName = "(none known)"
	}
	lgEngine.Info("a CSYNC in a SYNC is rejected: it is not from the zone's delegation sync leader", "zone", u.Zone, "sender", senderName, "originator", u.AgentId, "leader", leaderName)

	var kept []core.RROperation
	var refused []RejectedItemInfo
	for _, op := range u.Update.Operations {
		if !strings.EqualFold(op.RRtype, csync) {
			kept = append(kept, op)
			continue
		}
		for _, rrStr := range op.Records {
			record := rrStr
			if rr, err := dns.NewRR(rrStr); err == nil {
				record = rr.String() // as the sender tracks it
			}
			refused = append(refused, RejectedItemInfo{Record: record, Reason: reason})
		}
	}
	u.Update.Operations = kept
	if u.OriginatingDistID != "" && msgQs != nil && msgQs.OnRemoteConfirmationReady != nil {
		// to the agent that sent it, which need not be the one it names
		msgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
			OriginatingDistID: u.OriginatingDistID,
			OriginatingSender: string(sender),
			Zone:              u.Zone,
			Status:            "REJECTED",
			Message:           reason,
			RejectedItems:     refused,
		})
	}
	return reason
}
