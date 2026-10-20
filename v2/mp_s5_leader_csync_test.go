/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * tdns-mp #175: the zone's CSYNC is the leader's. It makes one when the
 * zone's NS set or glue differs from the parent's, sends it to every
 * provider as a contribution, and lets a NOTIFY(CSYNC) leave when each of
 * them has given its final confirmation and the zone's wait has passed. A
 * receiving agent takes a CSYNC from the zone's leader only.
 *
 * What is real here, on the agent under test: the delegation syncher with
 * tdns's analysis and sync against a parent on the loopback; the agent's
 * data engine with its repo and its tracking of who has confirmed what;
 * the enqueueing into the transport's reliable queue; the transport's
 * confirmation callback; the chain; and, for a SYNC that the agent
 * receives, its transport's routing, its message handler and the final
 * confirmation that goes back to the sender over the wire.
 *
 * What stands in: the other providers and the agent's own combiner. The
 * reliable queue's worker is not started, so nothing of the CSYNC leaves on
 * the wire; the test reads the queue to see who it is for, and gives each
 * recipient's final confirmation to the transport's confirmation callback,
 * as a confirmation that arrived would be given.
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	rigCombiner     = "combiner.alice.example."
	logCsyncMade    = `msg="made a CSYNC for the zone and sent it to the zone's providers"`
	logCsyncWaits   = `msg="a NOTIFY to the parent waits for the providers' confirmations of the zone's CSYNC"`
	logCsyncStill   = `msg="the NOTIFY to the parent still waits for the providers' confirmations of the zone's CSYNC"`
	logCsyncAllIn   = `msg="every provider has confirmed the zone's CSYNC"`
	logCsyncRefused = `msg="a CSYNC in a SYNC is rejected: it is not from the zone's delegation sync leader"`
	logCsyncFailed  = `msg="the zone's CSYNC was rejected"`
)

// startDataEngine runs the agent's data engine on the rig's transport, with
// a combiner configured, and waits until it answers.
func (r *notifyRig) startDataEngine(t *testing.T, ctx context.Context, engines *sync.WaitGroup) {
	t.Helper()
	msgQs := r.us.MsgQs
	msgQs.SynchedDataUpdate = make(chan *SynchedDataUpdate, 16)
	msgQs.SynchedDataCmd = make(chan *SynchedDataCmd, 4)
	msgQs.Confirmation = make(chan *ConfirmationDetail, 64)
	r.us.Bridge.combinerID = rigCombiner
	r.conf.InternalMp.MsgQs = msgQs
	engines.Add(1)
	go func() {
		defer engines.Done()
		r.conf.SynchedDataEngine(ctx, msgQs)
	}()
	r.repo(t)
}

// repo is what the agent's data engine holds for the zone, per contributing
// agent, as an operator is shown it.
func (r *notifyRig) repo(t *testing.T) map[AgentId]map[uint16][]TrackedRRInfo {
	t.Helper()
	answer := make(chan *SynchedDataCmdResponse, 1)
	r.us.MsgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "dump-zonedatarepo", Zone: ZoneName(r.mpzd.ZoneName), Response: answer}
	resp, ok := recvWithin(answer, 10*time.Second)
	if !ok || resp.Error {
		t.Fatalf("the data engine did not answer: %+v", resp)
	}
	return resp.ZDR[ZoneName(r.mpzd.ZoneName)]
}

// csync waits for the agent's own CSYNC in its repo to be another one than
// previous, and returns it as tracked and as a record.
func (r *notifyRig) csync(t *testing.T, previous string) (TrackedRRInfo, *dns.CSYNC) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		for _, info := range r.repo(t)[r.lem.localID][dns.TypeCSYNC] {
			if info.RR == previous || info.State == RRStateRemoved.String() {
				continue
			}
			rr, err := dns.NewRR(info.RR)
			if err != nil {
				t.Fatalf("the CSYNC in the repo: %v", err)
			}
			return info, rr.(*dns.CSYNC)
		}
	}
	t.Fatalf("the leader made no CSYNC\n%s", r.log)
	return TrackedRRInfo{}, nil
}

// queuedFor is who the transport's reliable queue holds a distribution for.
func (r *notifyRig) queuedFor(distID string) []string {
	var recipients []string
	for _, m := range r.us.Bridge.ReliableQueue.GetPendingMessages() {
		if m.DistributionID == distID && m.Zone == r.mpzd.ZoneName {
			recipients = append(recipients, m.RecipientID)
		}
	}
	sort.Strings(recipients)
	return recipients
}

// confirms is a recipient's final confirmation of a distribution arriving
// at the agent's transport: the record is held there.
func (r *notifyRig) confirms(from, distID, record string) {
	r.us.Bridge.ChunkHandler.OnConfirmationReceived(distID, from, transport.ConfirmSuccess, r.mpzd.ZoneName,
		[]string{record}, nil, nil, nil, false, "")
}

// rejects is a recipient's final confirmation that refuses the record.
func (r *notifyRig) rejects(from, distID, record, reason string) {
	r.us.Bridge.ChunkHandler.OnConfirmationReceived(distID, from, transport.ConfirmRejected, r.mpzd.ZoneName,
		nil, nil, []transport.RejectedItemDTO{{Record: record, Reason: reason}}, nil, false, "")
}

// logs waits for the engine's log to have the text.
func (r *notifyRig) logs(t *testing.T, text string) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if strings.Contains(r.log.String(), text) {
			return
		}
	}
	t.Errorf("the engine did not log %q\n%s", text, r.log)
}

// awaitedEvery sets how often the leader says that a NOTIFY still waits.
func awaitedEvery(t *testing.T, d time.Duration) {
	t.Helper()
	saved := delegationCsyncAwaitedEvery
	delegationCsyncAwaitedEvery = d
	t.Cleanup(func() { delegationCsyncAwaitedEvery = saved })
}

// An NS change on a parent that takes only NOTIFY. The leader makes one
// CSYNC with the immediate flag and sends it to the other provider's agent
// and to its own combiner. The NOTIFY(CSYNC) does not leave before the last
// of them has confirmed, then not before the zone's wait has passed since
// that confirmation, and then leaves; the checks of the parent follow.
func TestTheNotifyOfAnNSChangeWaitsForTheCsyncsConfirmationsAndThenForTheWait(t *testing.T) {
	const wait, delay = 500 * time.Millisecond, 300 * time.Millisecond
	awaitedEvery(t, time.Hour)
	r := newNotifyRigFor(t, "confirmed.csync.example.", "NOTIFY", true, repeat(delay, 400)...)
	r.propagation(wait)
	z := r.mpzd.ZoneName
	peer := r.peer.Identity
	r.parent.holdsNS("ns1."+z, r.oldNS)

	before := uint32(time.Now().Unix())
	r.hint()
	info, csync := r.csync(t, "")
	if csync.Flags != csyncFlagImmediate || csync.Hdr.Ttl != 120 || !slices.Equal(csync.TypeBitMap, []uint16{dns.TypeA, dns.TypeNS, dns.TypeAAAA}) {
		t.Errorf("the leader made the CSYNC %s, want the immediate flag only, the types A NS AAAA and TTL 120", info.RR)
	}
	if serialNewer(before, csync.Serial) || serialNewer(csync.Serial, uint32(time.Now().Unix())) {
		t.Errorf("the CSYNC's serial is %d, want the time it was made (%d or shortly after)", csync.Serial, before)
	}
	if got := r.queuedFor(info.DistributionID); !slices.Equal(got, []string{peer, rigCombiner}) {
		t.Errorf("the CSYNC is queued for %v, want the other provider's agent and our combiner", got)
	}
	r.logged(t, 1, logCsyncMade+" zone="+z+fmt.Sprintf(" serial=%d", csync.Serial))
	r.logged(t, 1, logCsyncWaits+" zone="+z+" notify=CSYNC"+fmt.Sprintf(" serial=%d", csync.Serial)+` awaited="[`+peer+" "+rigCombiner+`]"`)

	// nobody has confirmed: the NOTIFY stays, however long the wait is
	r.quiet(t, wait+200*time.Millisecond, "before any provider had confirmed the CSYNC")
	r.confirms(rigCombiner, info.DistributionID, info.RR)
	r.quiet(t, wait+200*time.Millisecond, "before the last provider had confirmed the CSYNC")
	if l := r.log.String(); strings.Contains(l, logCsyncAllIn) || strings.Contains(l, logHeld) {
		t.Errorf("the wait began with a confirmation missing:\n%s", l)
	}

	// the last confirmation: the zone's wait begins here
	last := time.Now()
	r.confirms(peer, info.DistributionID, info.RR)
	r.notified(t, "the NOTIFY after the confirmations and the wait", dns.TypeCSYNC)
	if d := time.Since(last); d < wait {
		t.Errorf("the NOTIFY left %s after the last confirmation, want the zone's wait from there: %s", d, wait)
	}
	r.logged(t, 1, logCsyncAllIn+" zone="+z+fmt.Sprintf(" serial=%d", csync.Serial))
	r.logged(t, 1, logHeld+" zone="+z+" notify=CSYNC wait=500ms largest="+string(r.lem.localID))
	r.logged(t, 1, logLeft+" zone="+z+" notify=CSYNC held=500ms")
	r.untold(t, 0, "before the parent was in sync")

	// the checks follow, at once and with no new CSYNC: nothing has changed
	r.notified(t, "the first check", dns.TypeCSYNC)
	if d := time.Since(last); d < wait+delay {
		t.Errorf("the first check sent %s after the last confirmation, want the wait and the first delay", d)
	}
	r.notified(t, "the second check", dns.TypeCSYNC)
	r.logged(t, 1, logCsyncMade)
	r.logged(t, 1, logCsyncWaits)
	r.logged(t, 1, logHeld)
	if again, _ := r.csync(t, ""); again.RR != info.RR {
		t.Errorf("a check of the parent made a new CSYNC: %s after %s", again.RR, info.RR)
	}
	r.parent.holdsNS("ns1." + z)
	if m := r.told(t, "the parent in sync"); !strings.Contains(m.Msg, "after NOTIFY(CSYNC)") {
		t.Errorf("the peer was told %+v", *m)
	}
}

// One provider does not confirm. No NOTIFY leaves, for as long as it takes;
// the leader says who is awaited, and says it again. When that provider
// confirms, the wait starts, and the NOTIFY leaves after it.
func TestANotifyDoesNotLeaveWhileAProviderHasNotConfirmedTheCsync(t *testing.T) {
	const wait, every = 300 * time.Millisecond, 200 * time.Millisecond
	awaitedEvery(t, every)
	r := newNotifyRigFor(t, "awaited.csync.example.", "NOTIFY", true, repeat(time.Minute, 4)...)
	r.propagation(wait)
	z := r.mpzd.ZoneName
	peer := r.peer.Identity
	r.parent.holdsNS("ns1."+z, r.oldNS)

	r.hint()
	info, csync := r.csync(t, "")
	r.confirms(rigCombiner, info.DistributionID, info.RR)
	// the other provider's agent says it has the SYNC and is working on it:
	// that is not its final word
	r.us.Bridge.ChunkHandler.OnConfirmationReceived(info.DistributionID, peer, transport.ConfirmPending, z, nil, nil, nil, nil, false, "")
	still := logCsyncStill + " zone=" + z + " notify=CSYNC" + fmt.Sprintf(" serial=%d", csync.Serial) + " awaited=[" + peer + "]"
	r.logs(t, still)
	r.quiet(t, 3*every, "while a provider had not confirmed the CSYNC")
	if n := strings.Count(r.log.String(), still); n < 3 {
		t.Errorf("the leader said %d times that the NOTIFY still waits for %s, want it said again and again\n%s", n, peer, r.log)
	}
	if l := r.log.String(); strings.Contains(l, logCsyncAllIn) || strings.Contains(l, logHeld) || strings.Contains(l, logLeft) {
		t.Errorf("the wait began, or the NOTIFY left, with a confirmation missing:\n%s", l)
	}

	last := time.Now()
	r.confirms(peer, info.DistributionID, info.RR)
	r.notified(t, "the NOTIFY after the missing confirmation", dns.TypeCSYNC)
	if d := time.Since(last); d < wait {
		t.Errorf("the NOTIFY left %s after the last confirmation, want the zone's wait from there: %s", d, wait)
	}
	r.logged(t, 1, logCsyncAllIn)
	// and nothing says that it still waits once it has left
	said := strings.Count(r.log.String(), logCsyncStill)
	r.quiet(t, 3*every, "a second time")
	if n := strings.Count(r.log.String(), logCsyncStill); n != said {
		t.Errorf("the leader went on saying that the NOTIFY waits after it had left (%d times, then %d)", said, n)
	}
}

// A provider rejects the CSYNC. The sync has failed: the NOTIFY that waited
// is dropped, the failure chain asks again, and that ask makes and
// distributes a new CSYNC.
func TestARejectedCsyncIsAFailedSyncAndTheNextAskDistributesAgain(t *testing.T) {
	rejectedCsync(t, "rejected.csync.example.", func(r *notifyRig, distID, record string) {
		r.rejects(r.peer.Identity, distID, record, "a CSYNC is taken only from the zone's delegation sync leader")
	})
}

// A provider's final word is that it failed, with nothing said of the
// record: it does not hold the CSYNC, and will not be heard again. That is
// a failed sync as well, not a confirmation to wait for.
func TestAProviderThatFailsWithoutNamingTheCsyncFailsTheSync(t *testing.T) {
	rejectedCsync(t, "failed.csync.example.", func(r *notifyRig, distID, record string) {
		r.us.Bridge.ChunkHandler.OnConfirmationReceived(distID, r.peer.Identity, transport.ConfirmFailed, r.mpzd.ZoneName, nil, nil, nil, nil, false, "")
	})
}

func rejectedCsync(t *testing.T, zone string, reject func(r *notifyRig, distID, record string)) {
	t.Helper()
	saved := delegationSyncFailureDelays
	delegationSyncFailureDelays = repeat(300*time.Millisecond, 8)
	t.Cleanup(func() { delegationSyncFailureDelays = saved })
	awaitedEvery(t, time.Hour)
	r := newNotifyRigFor(t, zone, "NOTIFY", true, repeat(time.Minute, 4)...)
	z := r.mpzd.ZoneName
	peer := r.peer.Identity
	r.parent.holdsNS("ns1."+z, r.oldNS)

	r.hint()
	first, csync := r.csync(t, "")
	r.logged(t, 1, logCsyncWaits)
	r.confirms(rigCombiner, first.DistributionID, first.RR)
	reject(r, first.DistributionID, first.RR)
	r.logged(t, 1, logCsyncFailed+" zone="+z+fmt.Sprintf(" serial=%d", csync.Serial)+" by="+peer)
	r.logged(t, 1, `msg="the NOTIFY that waited for the zone's CSYNC is dropped: the CSYNC was rejected" zone=`+z+" notify=CSYNC")
	r.logged(t, 1, `msg="the delegation sync failed; asking again" zone=`+z+" failure=1 in=300ms")

	// the failure chain's ask: a new CSYNC, newer than the rejected one
	second, again := r.csync(t, first.RR)
	if !serialNewer(again.Serial, csync.Serial) {
		t.Errorf("the CSYNC after the rejection has serial %d, the rejected one %d", again.Serial, csync.Serial)
	}
	r.logged(t, 2, logCsyncMade)
	r.quiet(t, 0, "for a CSYNC that a provider rejected")
	r.confirms(rigCombiner, second.DistributionID, second.RR)
	r.confirms(peer, second.DistributionID, second.RR)
	r.notified(t, "the NOTIFY for the CSYNC that every provider took", dns.TypeCSYNC)
	r.quiet(t, 300*time.Millisecond, "a second time")
}

// A parent that takes UPDATE gets its UPDATE at once: it carries the change
// itself, and waits for nobody. The CSYNC is made and distributed beside
// it all the same.
func TestAnUpdateGoesAtOnceAndTheCsyncIsDistributedBesideIt(t *testing.T) {
	awaitedEvery(t, time.Hour)
	r := newNotifyRigFor(t, "update.csync.example.", "UPDATE", true, repeat(30*time.Millisecond, 400)...)
	r.propagation(time.Hour)
	z := r.mpzd.ZoneName
	if _, err := r.mpzd.KeyDB.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: z,
		Keyname: z, Algorithm: dns.ED25519, State: tdns.Sig0StateActive, Creator: "test"}); err != nil {
		t.Fatalf("the zone's SIG(0) key: %v", err)
	}
	r.parent.holdsNS("ns1."+z, r.oldNS)
	r.hint()
	// no provider confirms anything, and the UPDATE is answered
	if m := r.told(t, "the UPDATE answered"); !strings.Contains(m.Msg, "SendUpdate(") {
		t.Errorf("the peer was told %+v", *m)
	}
	if n := r.parent.updatesSeen(); n != 1 {
		t.Errorf("the parent got %d UPDATEs, want the one", n)
	}
	info, csync := r.csync(t, "")
	if csync.Flags != csyncFlagImmediate {
		t.Errorf("the CSYNC beside the UPDATE is %s", info.RR)
	}
	if got := r.queuedFor(info.DistributionID); !slices.Equal(got, []string{r.peer.Identity, rigCombiner}) {
		t.Errorf("the CSYNC is queued for %v, want the other provider's agent and our combiner", got)
	}
	r.logged(t, 1, logCsyncMade)
	r.quiet(t, 300*time.Millisecond, "by the UPDATE scheme")
	if l := r.log.String(); strings.Contains(l, logCsyncWaits) || strings.Contains(l, logHeld) {
		t.Errorf("a sync sent as an UPDATE waited:\n%s", l)
	}
	// the confirmations arrive later and are booked; nothing else happens
	r.confirms(rigCombiner, info.DistributionID, info.RR)
	r.confirms(r.peer.Identity, info.DistributionID, info.RR)
	r.logged(t, 1, logCsyncAllIn)
	r.quiet(t, 200*time.Millisecond, "when the CSYNC beside an UPDATE was confirmed")
}

// The delegation's data changes again while the first CSYNC is on its way.
// A newer CSYNC takes its place, the confirmations of the first count for
// nothing, and one NOTIFY leaves in the end.
func TestASecondChangeDuringTheDistributionReplacesTheCsync(t *testing.T) {
	const wait = 300 * time.Millisecond
	awaitedEvery(t, time.Hour)
	r := newNotifyRigFor(t, "again.csync.example.", "NOTIFY", true, repeat(time.Minute, 4)...)
	r.propagation(wait)
	z := r.mpzd.ZoneName
	peer := r.peer.Identity
	r.parent.holdsNS("ns1."+z, r.oldNS)

	r.hint()
	first, csync1 := r.csync(t, "")
	r.logged(t, 1, logCsyncWaits)
	r.confirms(rigCombiner, first.DistributionID, first.RR)

	// the difference to the parent is another one now
	r.parent.holdsNS("ns1."+z, r.oldNS, "gone2.provider.example.")
	r.hint()
	second, csync2 := r.csync(t, first.RR)
	if !serialNewer(csync2.Serial, csync1.Serial) {
		t.Errorf("the second CSYNC has serial %d, the first %d", csync2.Serial, csync1.Serial)
	}
	r.logged(t, 2, logCsyncMade)
	r.logged(t, 1, logCsyncMade+" zone="+z+fmt.Sprintf(" serial=%d", csync2.Serial)+` why="the difference between the zone's NS set or glue and the parent's has changed"`)
	if held := r.repo(t)[r.lem.localID][dns.TypeCSYNC]; len(held) != 1 || held[0].RR != second.RR {
		t.Errorf("the leader's repo holds the CSYNC records %+v, want only the second", held)
	}

	// the first one's last confirmation comes late: it is not the zone's
	// CSYNC any more
	r.confirms(peer, first.DistributionID, first.RR)
	r.quiet(t, wait+200*time.Millisecond, "for the CSYNC that was replaced")
	if l := r.log.String(); strings.Contains(l, logCsyncAllIn) {
		t.Errorf("the confirmations of the replaced CSYNC counted:\n%s", l)
	}

	r.confirms(rigCombiner, second.DistributionID, second.RR)
	last := time.Now()
	r.confirms(peer, second.DistributionID, second.RR)
	r.notified(t, "the one NOTIFY", dns.TypeCSYNC)
	if d := time.Since(last); d < wait {
		t.Errorf("the NOTIFY left %s after the last confirmation, want the zone's wait: %s", d, wait)
	}
	r.quiet(t, wait+300*time.Millisecond, "a second time")
	r.logged(t, 1, logLeft)
}

// An election asks for a sync at every renewal of the lease, and an
// operator may ask at any time. Such a sync finds the difference the CSYNC
// was made for: it makes no new one, while the confirmations are awaited
// and while the wait runs, and the wait is not started anew.
func TestAnElectionDuringTheWaitMakesNoNewCsync(t *testing.T) {
	const wait = time.Second
	awaitedEvery(t, time.Hour)
	r := newNotifyRigFor(t, "election.csync.example.", "NOTIFY", true, repeat(time.Minute, 4)...)
	r.propagation(wait)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS)
	ask := func(what string) {
		t.Helper()
		answer := make(chan tdns.DelegationSyncStatus, 1)
		r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: z, ZoneData: r.mpzd.ZoneData, Response: answer}
		if st, ok := recvWithin(answer, 10*time.Second); !ok || st.Error || !strings.Contains(st.Msg, "(held: ") {
			t.Errorf("%s: the sync was answered %q (error %v, answered %v)", what, st.Msg, st.Error, ok)
		}
	}

	r.hint()
	info, _ := r.csync(t, "")
	r.logged(t, 1, logCsyncWaits)
	ask("while the confirmations were awaited")
	r.confirms(rigCombiner, info.DistributionID, info.RR)
	last := time.Now()
	r.confirms(r.peer.Identity, info.DistributionID, info.RR)
	r.logged(t, 1, logHeld)
	ask("while the wait ran")
	r.notified(t, "the held NOTIFY", dns.TypeCSYNC)
	if d := time.Since(last); d < wait || d > wait+800*time.Millisecond {
		t.Errorf("the NOTIFY left %s after the last confirmation, want the one wait of %s", d, wait)
	}
	r.logged(t, 1, logCsyncMade)
	r.logged(t, 1, logCsyncWaits)
	r.logged(t, 1, logHeld)
	if again, _ := r.csync(t, ""); again.RR != info.RR {
		t.Errorf("a sync that found the same difference made a new CSYNC: %s after %s", again.RR, info.RR)
	}
	r.quiet(t, 300*time.Millisecond, "for each of the syncs")
}

// The chain's own checks of the parent make no CSYNC, also when a check
// finds another difference than the one the CSYNC was made for: the parent
// has taken part of the change, and the zone is as it was. An election
// after such a check finds nothing new either.
func TestACheckThatFindsTheParentPartWayMakesNoNewCsync(t *testing.T) {
	const delay = 400 * time.Millisecond
	awaitedEvery(t, time.Hour)
	r := newNotifyRigFor(t, "partway.csync.example.", "NOTIFY", true, delay, time.Hour)
	z := r.mpzd.ZoneName
	r.parent.holdsNS("ns1."+z, r.oldNS, "gone2.provider.example.")

	r.hint()
	info, _ := r.csync(t, "")
	r.confirms(rigCombiner, info.DistributionID, info.RR)
	r.confirms(r.peer.Identity, info.DistributionID, info.RR)
	r.notified(t, "the NOTIFY of the change", dns.TypeCSYNC)
	// the parent scans, and drops one of the two nameservers
	r.parent.holdsNS("ns1."+z, "gone2.provider.example.")
	r.notified(t, "the first check", dns.TypeCSYNC) // at once: nothing waits for a confirmation
	r.logged(t, 1, logCheckAgain+" zone="+z+" notify=CSYNC check=2 in=1h0m0s")
	if !r.conf.requestDelegationSync(r.ctx, z, "this agent was elected the zone's delegation sync leader") {
		t.Fatal("the election's request was not queued")
	}
	r.notified(t, "the election's sync", dns.TypeCSYNC)
	r.logged(t, 1, logCsyncMade)
	r.logged(t, 1, logCsyncWaits) // the one of the change itself
	if again, _ := r.csync(t, ""); again.RR != info.RR {
		t.Errorf("a new CSYNC was made with the zone as it was: %s after %s", again.RR, info.RR)
	}
}

// receives hands a SYNC from another agent to the agent's transport as it
// arrives there over DNS, sender established, and to the agent's message
// handler, as the agent's sync engine does with what the transport queues.
// The agent's confirmations go back over DNS, the SYNC's mechanism.
func (r *notifyRig) receives(t *testing.T, originator, transportSender string, ops ...core.RROperation) string {
	t.Helper()
	distID := nextDistributionID()
	body, err := json.Marshal(DnsSyncPayload{
		MessageType:    "sync",
		OriginatorID:   originator,
		YourIdentity:   r.us.Identity,
		Zone:           r.mpzd.ZoneName,
		Operations:     ops,
		Time:           time.Now().Format(time.RFC3339Nano),
		Timestamp:      time.Now().Unix(),
		DistributionID: distID,
	})
	if err != nil {
		t.Fatalf("the SYNC: %v", err)
	}
	r.us.Bridge.routeIncomingMessage(&transport.IncomingMessage{
		TypeToken:       "sync",
		DistributionID:  distID,
		SenderID:        originator,
		TransportSender: transportSender,
		Mechanism:       transport.MechanismDNS,
		Zone:            r.mpzd.ZoneName,
		Payload:         body,
		ReceivedAt:      time.Now(),
		SourceAddr:      "127.0.0.1:0",
	})
	amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 10*time.Second)
	if !ok {
		t.Fatal("the transport did not queue the SYNC")
	}
	r.us.Registry.MsgHandler(amp, r.us.MsgQs.SynchedDataUpdate, r.us.MsgQs.SynchedDataCmd)
	return distID
}

// answered waits for the agent's final confirmation of a distribution to
// arrive at the sender, over the wire.
func (r *notifyRig) answered(t *testing.T, distID string) *ConfirmationDetail {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); {
		c, ok := recvWithin(r.peer.MsgQs.Confirmation, time.Until(end))
		if !ok {
			break
		}
		if c.DistributionID == distID && c.Status != "PENDING" {
			return c
		}
	}
	t.Fatalf("the sender got no final confirmation of %s\n%s", distID, r.log)
	return nil
}

// receivingRig is the rig with the agent under test as a provider that
// receives, and the peer as the sender, which the agent can answer over the
// wire.
func receivingRig(t *testing.T, zone string) *notifyRig {
	t.Helper()
	r := newNotifyRigFor(t, zone, "NOTIFY", true, repeat(time.Minute, 4)...)
	r.us.Registry.S.Set(AgentId(r.peer.Identity), NewAgent(AgentId(r.peer.Identity)))
	return r
}

func csyncOp(zone string, serial uint32) (core.RROperation, string) {
	rec := csyncRecord(zone, serial, csyncFlagImmediate)
	return core.RROperation{Operation: "replace", RRtype: "CSYNC", Records: []string{rec}}, rec
}

// A CSYNC in a SYNC from the zone's leader is taken: it goes into the
// agent's repo under the leader's name and on to the agent's combiner, and
// when the combiner has confirmed, the leader gets the agent's final
// confirmation.
func TestACsyncFromTheLeaderIsTakenAndReachesTheCombiner(t *testing.T) {
	r := receivingRig(t, "taken.csync.example.")
	z := r.mpzd.ZoneName
	leader := AgentId(r.peer.Identity)
	r.leader(leader)
	op, rec := csyncOp(z, 1000)

	distID := r.receives(t, string(leader), string(leader), op)
	var held TrackedRRInfo
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end) && held.RR == ""; time.Sleep(10 * time.Millisecond) {
		if got := r.repo(t)[leader][dns.TypeCSYNC]; len(got) == 1 {
			held = got[0]
		}
	}
	if held.RR != rec {
		t.Fatalf("the agent's repo holds the leader's CSYNC %+v, want %s\n%s", held, rec, r.log)
	}
	if got := r.queuedFor(held.DistributionID); !slices.Equal(got, []string{rigCombiner}) {
		t.Fatalf("the leader's CSYNC is queued for %v, want our combiner", got)
	}
	// the combiner's confirmation, and then the agent's own to the leader
	r.confirms(rigCombiner, held.DistributionID, rec)
	c := r.answered(t, distID)
	if c.Status != "SUCCESS" || c.Source != r.us.Identity || !slices.Equal(c.AppliedRecords, []string{rec}) || len(c.RejectedItems) != 0 {
		t.Errorf("the leader got the final confirmation %+v", *c)
	}
	if l := r.log.String(); strings.Contains(l, logCsyncRefused) {
		t.Errorf("the leader's CSYNC was rejected:\n%s", l)
	}
}

// A CSYNC from an agent that is not the zone's leader is rejected, and so
// is any CSYNC while no leader is known. The sender is told why in a final
// confirmation, and nothing of it reaches the repo or the combiner. What
// else the SYNC carries is processed as usual.
func TestACsyncFromAnyoneButTheLeaderIsRejected(t *testing.T) {
	r := receivingRig(t, "refused.csync.example.")
	z := r.mpzd.ZoneName
	sender := r.peer.Identity
	op, rec := csyncOp(z, 1000)
	rejected := func(what, distID, reason string) {
		t.Helper()
		c := r.answered(t, distID)
		if c.Status != "REJECTED" || len(c.RejectedItems) != 1 || c.RejectedItems[0].Record != rec || c.RejectedItems[0].Reason != reason {
			t.Errorf("%s: the sender got the final confirmation %+v, want a rejection of the CSYNC for %q", what, *c, reason)
		}
		if got := r.repo(t)[AgentId(sender)][dns.TypeCSYNC]; len(got) != 0 {
			t.Errorf("%s: the agent's repo holds the CSYNC %+v", what, got)
		}
		for _, m := range r.us.Bridge.ReliableQueue.GetPendingMessages() {
			if m.RecipientID == rigCombiner && !strings.Contains(what, "beside") {
				t.Errorf("%s: something was queued for the combiner: %+v", what, m)
			}
		}
	}

	// the agent under test leads the zone itself; the sender does not
	r.leader(r.lem.localID)
	rejected("another member", r.receives(t, sender, sender, op),
		"a CSYNC is taken only from the zone's delegation sync leader: the sender is "+sender+", the leader is "+string(r.lem.localID))
	r.logged(t, 1, logCsyncRefused+" zone="+z+" sender="+sender+" originator="+sender+" leader="+string(r.lem.localID))

	// the sender says the CSYNC comes from the leader; the transport knows
	// who sent it
	rejected("another member in the leader's name", r.receives(t, string(r.lem.localID), sender, op),
		"a CSYNC is taken only from the zone's delegation sync leader: the sender is "+sender+", the leader is "+string(r.lem.localID))

	// no leader is known: the lease has run out, or no election was held
	r.lem.mu.Lock()
	delete(r.lem.elections, ZoneName(z))
	r.lem.mu.Unlock()
	rejected("no leader known", r.receives(t, sender, sender, op),
		"a CSYNC is taken only from the zone's delegation sync leader: the sender is "+sender+", and no leader is known")
	r.logged(t, 1, logCsyncRefused+" zone="+z+" sender="+sender+" originator="+sender+` leader="(none known)"`)

	// an NS record beside the CSYNC is the sender's own contribution, and
	// is taken
	ns := fmt.Sprintf("%s\t3600\tIN\tNS\tns9.provider.example.", z)
	rejected("a CSYNC beside an NS record", r.receives(t, sender, sender, op, core.RROperation{Operation: "replace", RRtype: "NS", Records: []string{ns}}),
		"a CSYNC is taken only from the zone's delegation sync leader: the sender is "+sender+", and no leader is known")
	var held []TrackedRRInfo
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end) && len(held) == 0; time.Sleep(10 * time.Millisecond) {
		held = r.repo(t)[AgentId(sender)][dns.TypeNS]
	}
	if len(held) != 1 || held[0].RR != ns {
		t.Errorf("the NS record beside the rejected CSYNC: the repo holds %+v", held)
	}
}

// The rule goes by the sender the transport established and by nothing
// else. A SYNC that carries no transport sender names its sender only in its
// payload, which can name anybody: the leader, too. Such a message is not
// queued at all. And an update that reaches the rule without a transport
// sender has its CSYNC rejected, whoever it says it is from.
func TestACsyncWithNoTransportSenderIsNotTaken(t *testing.T) {
	r := receivingRig(t, "nosender.csync.example.")
	z := r.mpzd.ZoneName
	peer := r.peer.Identity
	r.leader(AgentId(peer)) // the peer leads the zone: its CSYNC would be taken
	op, _ := csyncOp(z, 1000)

	body, err := json.Marshal(DnsSyncPayload{
		MessageType:    "sync",
		OriginatorID:   peer,
		YourIdentity:   r.us.Identity,
		Zone:           z,
		Operations:     []core.RROperation{op},
		Time:           time.Now().Format(time.RFC3339Nano),
		Timestamp:      time.Now().Unix(),
		DistributionID: "no-transport-sender",
	})
	if err != nil {
		t.Fatalf("the SYNC: %v", err)
	}
	r.us.Bridge.routeIncomingMessage(&transport.IncomingMessage{
		TypeToken:      "sync",
		DistributionID: "no-transport-sender",
		SenderID:       peer, // the payload's word, and the only one
		Zone:           z,
		Payload:        body,
		ReceivedAt:     time.Now(),
		SourceAddr:     "127.0.0.1:0",
	})
	if amp, ok := recvMsgWithin(t, r.us.MsgQs.Msg, 300*time.Millisecond); ok {
		t.Fatalf("a SYNC with no transport sender was queued: %+v", amp)
	}

	// The rule itself, for an update that reaches it by another way.
	u := &SynchedDataUpdate{
		Zone:       ZoneName(z),
		AgentId:    AgentId(peer),
		UpdateType: "remote",
		Update:     &ZoneUpdate{Zone: ZoneName(z), AgentId: AgentId(peer), Operations: []core.RROperation{op}},
	}
	reason := r.conf.refuseCsyncNotFromLeader(u, r.us.MsgQs)
	if !strings.Contains(reason, "the sender is (not established)") {
		t.Errorf("a CSYNC in an update with no transport sender, in the leader's name: reason %q, want it rejected", reason)
	}
	if len(u.Update.Operations) != 0 {
		t.Errorf("the CSYNC stayed in the update: %+v", u.Update.Operations)
	}
}

// The leadership has moved to this agent, and its clock is behind the
// previous leader's. Its CSYNC must still be the newer one at every
// combiner, so its serial is one more than the newest it knows of.
func TestANewLeadersCsyncIsNewerThanThePreviousLeaders(t *testing.T) {
	awaitedEvery(t, time.Hour)
	r := receivingRig(t, "moved.csync.example.")
	z := r.mpzd.ZoneName
	previous := AgentId(r.peer.Identity)
	r.parent.holdsNS("ns1."+z, r.oldNS)

	// the previous leader's CSYNC, a day ahead of this agent's clock,
	// arrived while it led
	ahead := uint32(time.Now().Add(24 * time.Hour).Unix())
	r.leader(previous)
	op, rec := csyncOp(z, ahead)
	r.receives(t, string(previous), string(previous), op)
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if got := r.repo(t)[previous][dns.TypeCSYNC]; len(got) == 1 && got[0].RR == rec {
			break
		}
	}

	r.leader(r.lem.localID)
	r.hint()
	info, csync := r.csync(t, "")
	if csync.Serial != ahead+1 {
		t.Errorf("the new leader's CSYNC is %s, want serial %d: one more than the previous leader's", info.RR, ahead+1)
	}
	// and a combiner that holds the previous leader's takes the new one
	mpzd, hdb := csyncCombinerZone(t, "moved.combiner.csync.example.", true, true)
	contributeCsync(mpzd, hdb, string(previous), csyncRecord(mpzd.ZoneName, ahead, csyncFlagImmediate))
	mine := csyncRecord(mpzd.ZoneName, csync.Serial, csync.Flags)
	if resp := contributeCsync(mpzd, hdb, string(r.lem.localID), mine); resp.Status != "ok" {
		t.Errorf("a combiner answered the new leader's CSYNC %q, rejected %+v", resp.Status, resp.RejectedItems)
	}
	wantServed(t, mpzd, "after the new leader's CSYNC", mine)
}
