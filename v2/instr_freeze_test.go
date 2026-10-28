package tdnsmp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The freeze (plan S6). It is dormant until the thaw enforces the active
// serial (S7): these tests set the active serial and the newest apart by
// hand, as S7 will.

const freezeCombiner = "combiner.a.role.example."

// freezeRecords are a and b, the two providers, and n, a record with no
// role, as seedRoles names them.
var freezeRecords = []string{
	`3600 IN HSYNC3 ON a a.role.example. .`,
	`3600 IN HSYNC3 ON b b.role.example. .`,
	`3600 IN HSYNC3 ON n n.role.example. .`,
}

// freezeAt is the zone's instructions at serial: servers and auditors as
// given; suffix tells two serials apart, a change with nothing to carry out.
func freezeAt(t *testing.T, serial uint32, suffix, servers, auditors string) *Instructions {
	t.Helper()
	param := fmt.Sprintf(`servers="%s" nsmgmt="agent" suffix="%s"`, servers, suffix)
	if auditors != "" {
		param += fmt.Sprintf(` auditors="%s"`, auditors)
	}
	return jAt(t, serial, param, freezeRecords...)
}

// keptDB is a keystore file of its own, with every table of the agent.
func keptDB(t *testing.T) (string, *HsyncDB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.db")
	if err := os.WriteFile(path, nil, 0664); err != nil {
		t.Fatal(err)
	}
	return path, openKeptDB(t, path)
}

func openKeptDB(t *testing.T, path string) *HsyncDB {
	t.Helper()
	kdb, err := tdns.NewKeyDB(path, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	t.Cleanup(func() { kdb.DB.Close() })
	hdb := NewHsyncDB(kdb)
	if err := hdb.InitHsyncTables(); err != nil {
		t.Fatal(err)
	}
	return hdb
}

// freezeRig is the agent of provider a, in a zone that a and b serve: its
// store and its lists on disk, its data engine's handling called directly,
// and what it sends landing in a reliable queue whose worker is not running.
type freezeRig struct {
	t     *testing.T
	conf  *Config
	zone  string
	zdr   *ZoneDataRepo
	queue *transport.ReliableMessageQueue
	store *InstructionStore
	hdb   *HsyncDB
	path  string
	n, v  *Instructions // the active serial, and the newer one agreed on
}

func newFreezeRig(t *testing.T, zone string) *freezeRig {
	t.Helper()
	asMPAgent(t)
	zd := seedRoles(t, zone, []string{roleA, roleB}, nil, []string{roleN})
	zd.Logger = log.New(io.Discard, "", 0)
	mpzd, _ := Zones.Get(zone)
	mpzd.EnsureMP()
	mpzd.MP.MPdata = &MPdata{WeAreProvider: true, OurLabel: "a"}
	path, hdb := keptDB(t)
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: roleA})
	queue := transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{})
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: conf.MpConfig()}
	conf.InternalMp.AgentRegistry = ar
	conf.InternalMp.MPTransport = &MPTransportBridge{
		TransportManager: &transport.TransportManager{ReliableQueue: queue, PeerRegistry: transport.NewPeerRegistry()},
		agentRegistry:    ar, combinerID: freezeCombiner, pendingDnskeyPropagations: map[string]*PendingDnskeyPropagation{},
	}
	conf.InternalMp.MsgQs = &MsgQs{SynchedDataUpdate: make(chan *SynchedDataUpdate, 16), SynchedDataCmd: make(chan *SynchedDataCmd, 16)}
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	r := &freezeRig{t: t, conf: conf, zone: zone, zdr: zdr, queue: queue, hdb: hdb, path: path}
	r.load()
	r.n = freezeAt(t, 41, "n", "a,b", "")
	r.v = freezeAt(t, 42, "v", "a,b", "")
	r.store.Note(zone, r.n, nil)
	enforced(t, r.store, zone)
	return r
}

// withSigner gives the agent a signer, whose hand-overs go to the queue
// returned, of a zone that is multi-provider here.
func (r *freezeRig) withSigner() *handedQueue {
	mpzd, _ := Zones.Get(r.zone)
	mpzd.Options[tdns.OptMultiProvider] = true
	tr, q := newTestTracker()
	tr.toSigner = true
	r.conf.InternalMp.SignerHandover = tr
	return q
}

// wanted is the hand-over the agent wants its signer to hold for the zone.
func (r *freezeRig) wanted() *ActingHandover {
	r.t.Helper()
	tr := r.conf.InternalMp.SignerHandover
	tr.mu.Lock()
	defer tr.mu.Unlock()
	z := tr.zones[handoverKey(r.zone)]
	if z == nil || z.want == nil {
		r.t.Fatal("the agent wants its signer to hold nothing for the zone")
	}
	return z.want
}

// confirm is the signer's inventory, now: it holds the hand-over the agent
// wants it to, and holds the zone's key machine or not.
func (r *freezeRig) confirm(hold bool) {
	r.t.Helper()
	r.conf.InternalMp.SignerHandover.learned(r.zone, r.wanted())
	mpzd, _ := Zones.Get(r.zone)
	mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: r.zone, Hold: hold, Received: time.Now()})
}

// lastHanded is the last hand-over among msgs.
func lastHanded(t *testing.T, msgs []handedMsg) *ActingHandover {
	t.Helper()
	if len(msgs) == 0 || msgs[len(msgs)-1].update.Acting == nil {
		t.Fatalf("no hand-over among %d messages", len(msgs))
	}
	return msgs[len(msgs)-1].update.Acting
}

// load reads the store and the lists from disk, as a start does.
func (r *freezeRig) load() {
	r.t.Helper()
	r.store = loadStore(r.t, r.hdb)
	prev := instrStore.Load()
	instrStore.Store(r.store)
	r.t.Cleanup(func() { instrStore.Store(prev) })
	kept, err := loadKeptLists(r.hdb)
	if err != nil {
		r.t.Fatal(err)
	}
	r.conf.InternalMp.Instructions, r.conf.InternalMp.Kept = r.store, kept
	r.store.onFreeze = r.conf.onFreeze
}

// agree has the agent hold v above its active serial: it agrees on it, and
// the zone is frozen.
func (r *freezeRig) agree() {
	r.t.Helper()
	r.store.Note(r.zone, r.v, nil)
	if why := r.conf.zoneFrozen(r.zone); len(why) == 0 {
		r.t.Fatal("the zone is not frozen while it agrees on a newer serial")
	}
}

// done thaws the zone to v and ends the transition, as S7 and S12 will.
func (r *freezeRig) done() {
	r.t.Helper()
	if err := r.store.Activate(r.zone, Thaw{From: sd(r.n), To: sd(r.v)}); err != nil {
		r.t.Fatalf("Activate: %v", err)
	}
	if err := r.store.Done(r.zone); err != nil {
		r.t.Fatalf("Done: %v", err)
	}
	r.conf.instrDone(context.Background(), r.zdr, ZoneName(r.zone))
}

// edit is the operator's NS edit, a replace of this provider's NS records,
// as add-rr makes it, handled by the data engine. It returns the answer.
func (r *freezeRig) edit(names ...string) *AgentMsgResponse {
	r.t.Helper()
	var records []string
	for _, name := range names {
		records = append(records, r.ns(name))
	}
	resp := make(chan *AgentMsgResponse, 1)
	r.conf.applyLocalUpdate(context.Background(), r.zdr, &SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: roleA, UpdateType: "local",
		Update: &ZoneUpdate{Zone: ZoneName(r.zone), AgentId: roleA,
			Operations: []core.RROperation{{Operation: "replace", RRtype: "NS", Records: records}}}, Response: resp})
	select {
	case a := <-resp:
		return a
	default:
		r.t.Fatal("the data engine gave the edit no answer")
	}
	return nil
}

func (r *freezeRig) ns(name string) string { return r.zone + " 3600 IN NS " + name }

// ownNS is this provider's NS records as its data holds them.
func (r *freezeRig) ownNS() []string {
	var out []string
	if ar, ok := r.zdr.Get(ZoneName(r.zone)); ok {
		if od, ok := ar.Get(roleA); ok {
			if rrset, ok := od.RRtypes.Get(dns.TypeNS); ok {
				for _, rr := range rrset.RRs {
					out = append(out, rr.(*dns.NS).Ns)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// sent is the number of messages queued for each recipient.
func (r *freezeRig) sent() map[string]int {
	out := map[string]int{}
	for _, m := range r.queue.GetPendingMessages() {
		out[m.RecipientID]++
	}
	return out
}

func TestAZoneIsFrozenWhileItAgreesReconcilesOrHoldsAnOwnerError(t *testing.T) {
	r := newFreezeRig(t, "reasons.freeze.example.")
	if why := r.conf.zoneFrozen(r.zone); len(why) != 0 {
		t.Fatalf("a steady zone is frozen: %v", why)
	}
	r.agree()
	if why := r.conf.zoneFrozen(r.zone); !slices.Equal(why, []string{"agreeing on 42"}) {
		t.Errorf("agreeing: %v", why)
	}
	if err := r.store.Activate(r.zone, Thaw{From: sd(r.n), To: sd(r.v)}); err != nil {
		t.Fatal(err)
	}
	if why := r.conf.zoneFrozen(r.zone); !slices.Equal(why, []string{"reconciling from 41 to 42"}) {
		t.Errorf("reconciling: %v", why)
	}
	if err := r.store.Done(r.zone); err != nil {
		t.Fatal(err)
	}
	if why := r.conf.zoneFrozen(r.zone); len(why) != 0 {
		t.Errorf("done: still frozen, %v", why)
	}
	// an edit without a raised serial is an owner error, which holds the zone
	r.store.Note(r.zone, freezeAt(t, 42, "other", "a,b", ""), nil)
	if why := r.conf.zoneFrozen(r.zone); len(why) != 1 || !strings.HasPrefix(why[0], "owner error: ") {
		t.Errorf("an owner error: %v", why)
	}
	// a refused newest serial with none agreed on leaves the zone steady
	// (design 3.6): the record of a provider with a role removed
	s := newFreezeRig(t, "refused.freeze.example.")
	s.store.Note(s.zone, jAt(t, 42, `servers="a,b"`, freezeRecords[0], freezeRecords[2]), nil)
	if st := s.store.Status(s.zone); st.Phase != PhaseRefused {
		t.Fatalf("the phase with the newest refused: %s", st.Phase)
	}
	if why := s.conf.zoneFrozen(s.zone); len(why) != 0 {
		t.Errorf("a refused newest serial froze the zone: %v", why)
	}
}

// Until the thaw enforces the active serial (S7), nothing is frozen: the
// active serial follows the copy, and an owner error is shown and not
// enforced.
func TestNothingIsFrozenUntilTheActiveSerialIsEnforced(t *testing.T) {
	s := newStore(t)
	s.Note(storeZone, at(t, 7, "alpha"), nil)
	s.Note(storeZone, at(t, 8, "beta"), nil)
	s.Note(storeZone, at(t, 8, "alpha,beta"), nil)
	if st := s.Status(storeZone); st.OwnerError == "" {
		t.Fatal("no owner error at an edit without a raised serial")
	}
	if why := s.frozen(storeZone); len(why) != 0 {
		t.Errorf("a zone whose active serial is not enforced is frozen: %v", why)
	}
}

func TestAnOperatorEditDuringAgreeingIsKept(t *testing.T) {
	r := newFreezeRig(t, "kept.freeze.example.")
	r.agree()
	before := r.sent()
	a := r.edit("ns1.a.example.")
	if a.Error || a.Kept != "agreeing on 42" {
		t.Fatalf("the edit's answer: %+v", a)
	}
	if got := r.ownNS(); len(got) != 0 {
		t.Errorf("a kept edit is in the data: %v", got)
	}
	if after := r.sent(); !maps.Equal(before, after) {
		t.Errorf("a kept edit was sent: %v, before %v", after, before)
	}
	if owed := r.conf.InternalMp.Kept.entries(r.zone, listOwed); len(owed) != 1 {
		t.Errorf("the owed list: %d entries, want the edit", len(owed))
	}
}

// A request for the zone's state is answered from the data: the kept edit
// is not in the answer, before "done".
func TestAKeptEditIsNotInACatchUpAnswer(t *testing.T) {
	r := newFreezeRig(t, "catchup.freeze.example.")
	r.edit("ns1.a.example.")
	r.agree()
	r.edit("ns1.a.example.", "ns2.a.example.")
	r.zdr.markOwnState(ZoneName(r.zone), true, "")
	zu := r.conf.buildCatchUpAnswer(r.zdr, ZoneName(r.zone), &CatchUp{Request: "r1", Reason: "start"})
	var names []string
	for _, s := range ops(zu)["NS"].Records {
		if rr, err := dns.NewRR(s); err == nil {
			names = append(names, rr.(*dns.NS).Ns)
		}
	}
	if !slices.Equal(names, []string{"ns1.a.example."}) {
		t.Errorf("the answer's NS: %v, want the record from before the freeze only", names)
	}
}

// A sync of this provider's own data, as the combiner's agent-resync asks
// for it, carries the data: the kept edit is not sent.
func TestAKeptEditIsNotInASync(t *testing.T) {
	r := newFreezeRig(t, "sync.freeze.example.")
	r.agree()
	r.edit("ns1.a.example.")
	r.zdr.markOwnState(ZoneName(r.zone), true, "")
	before := r.sent()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.conf.SynchedDataEngine(ctx, r.conf.InternalMp.MsgQs) }()
	t.Cleanup(func() { cancel(); <-done })
	resp := make(chan *SynchedDataCmdResponse, 1)
	r.conf.InternalMp.MsgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "resync-targeted", Zone: ZoneName(r.zone), TargetAgent: roleB, Response: resp}
	select {
	case <-resp:
	case <-time.After(10 * time.Second):
		t.Fatal("the resync got no answer")
	}
	if after := r.sent(); after[roleB] != before[roleB] {
		t.Errorf("a sync of no data sent %d messages to b", after[roleB]-before[roleB])
	}
}

// The operator's second edit sees the first: the owed changes are laid over
// the data.
func TestASecondKeptEditSeesTheFirst(t *testing.T) {
	r := newFreezeRig(t, "second.freeze.example.")
	r.edit("ns1.a.example.")
	r.agree()
	r.edit("ns1.a.example.", "ns2.a.example.")
	base := map[uint16][]dns.RR{}
	for _, s := range []string{r.ns("ns1.a.example.")} {
		rr, _ := dns.NewRR(s)
		base[dns.TypeNS] = append(base[dns.TypeNS], rr)
	}
	seen := overOwed(base, r.conf.InternalMp.Kept.entries(r.zone, listOwed))
	var names []string
	for _, rr := range seen[dns.TypeNS] {
		names = append(names, rr.(*dns.NS).Ns)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"ns1.a.example.", "ns2.a.example."}) {
		t.Errorf("the data with the owed list laid over: %v", names)
	}
	// a delete, as update-local-zonedata sends it
	del, _ := dns.NewRR(r.zone + " 0 NONE NS ns1.a.example.")
	k := keptUpdateOf(&SynchedDataUpdate{Update: &ZoneUpdate{RRsets: map[uint16]core.RRset{dns.TypeNS: {RRs: []dns.RR{del}}}}})
	back, err := k.zoneUpdate(ZoneName(r.zone), roleA)
	if err != nil || back.RRsets[dns.TypeNS].RRs[0].Header().Class != dns.ClassNONE {
		t.Fatalf("an owed delete read back: %v, %v", back, err)
	}
	seen = overOwed(seen, []keptEntry{{Update: k}})
	if len(seen[dns.TypeNS]) != 1 || seen[dns.TypeNS][0].(*dns.NS).Ns != "ns2.a.example." {
		t.Errorf("after the owed delete: %v", seen[dns.TypeNS])
	}
}

func TestKeptEditsGoOutInOrderWhenTheTransitionIsDone(t *testing.T) {
	r := newFreezeRig(t, "order.freeze.example.")
	r.agree()
	r.edit("ns1.a.example.")
	r.edit("ns1.a.example.", "ns2.a.example.")
	r.edit("ns1.a.example.", "ns2.a.example.") // a repeat is owed once
	if owed := r.conf.InternalMp.Kept.entries(r.zone, listOwed); len(owed) != 2 {
		t.Fatalf("the owed list: %d entries, want the two edits", len(owed))
	}
	before := r.sent()
	r.done()
	if got := r.ownNS(); !slices.Equal(got, []string{"ns1.a.example.", "ns2.a.example."}) {
		t.Errorf("after done, the data: %v, want the second edit's set", got)
	}
	if after := r.sent(); after[roleB]-before[roleB] != 2 || after[freezeCombiner]-before[freezeCombiner] != 2 {
		t.Errorf("after done, sent %v (before %v), want each edit to b and the combiner", after, before)
	}
	if owed := r.conf.InternalMp.Kept.entries(r.zone, listOwed); len(owed) != 0 {
		t.Errorf("after done, %d entries owed", len(owed))
	}
}

// At the release the recipients are read then: the members the active
// instructions name, not those of the serial the edit was made under.
func TestAKeptEditGoesToTheMembersOfTheNewInstructions(t *testing.T) {
	r := newFreezeRig(t, "members.freeze.example.")
	r.v = freezeAt(t, 42, "v", "a,b", "n") // n an auditor: a change with nothing to carry out
	r.agree()
	r.edit("ns1.a.example.")
	if n := r.sent()[roleN]; n != 0 {
		t.Fatalf("n was sent %d messages before the release", n)
	}
	r.done()
	if n := r.sent()[roleN]; n != 1 {
		t.Errorf("n, an auditor under the new instructions, was sent %d messages, want the kept edit", n)
	}
}

func TestAKeptEditIsDroppedWhenTheProviderHasLostItsRole(t *testing.T) {
	r := newFreezeRig(t, "lost.freeze.example.")
	r.agree()
	r.edit("ns1.a.example.")
	r.zdr.markOwnState(ZoneName(r.zone), true, "")
	// the transition took a's role, as a removal will (S17b); set by hand,
	// as the judge refuses that kind of change until then
	if err := r.store.update(r.zone, func(z *zoneSerials) error {
		gone := freezeAt(t, 42, "v", "b", "")
		z.Active = &heldSerial{SerialDigest: sd(gone), Reading: gone, Since: time.Now()}
		z.Held = nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := r.sent()
	r.conf.instrDone(context.Background(), r.zdr, ZoneName(r.zone))
	if after := r.sent(); !maps.Equal(before, after) {
		t.Errorf("an edit of a provider with no role went out: %v, before %v", after, before)
	}
	if owed := r.conf.InternalMp.Kept.entries(r.zone, listOwed); len(owed) != 0 {
		t.Errorf("%d entries still owed", len(owed))
	}
	if r.zdr.OwnStateRead(ZoneName(r.zone)) {
		t.Error("the own state is not read again after the kept changes were dropped")
	}
}

func TestTheListsSurviveARestart(t *testing.T) {
	r := newFreezeRig(t, "restart.freeze.example.")
	r.agree()
	r.edit("ns1.a.example.")
	r.edit("ns1.a.example.", "ns2.a.example.")
	want := r.conf.InternalMp.Kept.entries(r.zone, listOwed)

	hdb := openKeptDB(t, r.path)
	r.hdb = hdb
	r.load()
	got := r.conf.InternalMp.Kept.entries(r.zone, listOwed)
	if len(got) != len(want) {
		t.Fatalf("after a restart %d entries owed, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Seq != want[i].Seq || !slices.Equal(got[i].Update.Operations[0].Records, want[i].Update.Operations[0].Records) {
			t.Errorf("entry %d after a restart: %+v, want %+v", i, got[i], want[i])
		}
	}
	if why := r.conf.zoneFrozen(r.zone); len(why) == 0 {
		t.Error("the zone is not frozen after a restart")
	}
	// the next entry is numbered after them
	r.edit("ns3.a.example.")
	if all := r.conf.InternalMp.Kept.entries(r.zone, listOwed); all[len(all)-1].Seq <= want[len(want)-1].Seq {
		t.Errorf("the entry after a restart is numbered %d", all[len(all)-1].Seq)
	}

	// and the signer's hold
	path, shdb := keptDB(t)
	holds, err := loadSignerHolds(shdb)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holds.set(r.zone, true); err != nil {
		t.Fatal(err)
	}
	again, err := loadSignerHolds(openKeptDB(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if !again.held(strings.ToUpper(r.zone)) {
		t.Error("the signer's hold is lost at a restart")
	}
}

// A DNSKEY distribution after the signer's inventory passes: a rollover
// under way, or an emergency one.
func TestARolloverUnderWayIsNotHeld(t *testing.T) {
	r := newFreezeRig(t, "rollover.freeze.example.")
	r.agree()
	key := testDnskey(t, r.zone, 257)
	before := r.sent()
	resp := make(chan *AgentMsgResponse, 1)
	r.conf.applyLocalUpdate(context.Background(), r.zdr, &SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: roleA, UpdateType: "local",
		Update: &ZoneUpdate{Zone: ZoneName(r.zone), AgentId: roleA, RRs: []dns.RR{key},
			Operations: []core.RROperation{{Operation: "replace", RRtype: "DNSKEY", Records: []string{key.String()}}}},
		SkipCombiner: true, DnskeyKeyTags: []uint16{key.KeyTag()}, Inventory: true, Response: resp})
	if a := <-resp; a.Error || a.Kept != "" {
		t.Fatalf("the distribution's answer: %+v", a)
	}
	if after := r.sent(); after[roleB]-before[roleB] != 1 {
		t.Errorf("the DNSKEY distribution reached b %d times, want once", after[roleB]-before[roleB])
	}
	if owed := r.conf.InternalMp.Kept.entries(r.zone, listOwed); len(owed) != 0 {
		t.Errorf("the distribution was owed: %d entries", len(owed))
	}
}

func TestResyncPushIsRefusedDuringATransition(t *testing.T) {
	r := newFreezeRig(t, "resync.freeze.example.")
	r.agree()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.conf.SynchedDataEngine(ctx, r.conf.InternalMp.MsgQs) }()
	t.Cleanup(func() { cancel(); <-done })
	resp := make(chan *SynchedDataCmdResponse, 1)
	r.conf.InternalMp.MsgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "resync", Zone: ZoneName(r.zone), Response: resp}
	select {
	case a := <-resp:
		if !a.Error || !strings.Contains(a.ErrorMsg, "resync --push is refused during the transition (agreeing on 42)") {
			t.Errorf("resync --push while frozen: %+v", a)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the resync got no answer")
	}
}

// What is not held: the answer to a request for the zone's state, which
// another member's catch-up waits for, and an update that is such an answer.
func TestCatchUpRequestsAndAnswersAreNotHeld(t *testing.T) {
	r := newFreezeRig(t, "answers.freeze.example.")
	r.edit("ns1.a.example.")
	r.agree()
	r.zdr.markOwnState(ZoneName(r.zone), true, "")
	before := r.sent()
	if _, err := r.conf.catchUpAnswer(r.zdr, ZoneName(r.zone), roleB, &CatchUp{Request: "r1", Reason: "start"}); err != nil {
		t.Fatalf("the answer during the freeze: %v", err)
	}
	if after := r.sent(); after[roleB]-before[roleB] != 1 {
		t.Errorf("the answer reached b %d times, want once", after[roleB]-before[roleB])
	}

	// b's answer to this agent's request, through the data engine: applied
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.conf.SynchedDataEngine(ctx, r.conf.InternalMp.MsgQs) }()
	t.Cleanup(func() { cancel(); <-done })
	theirs := r.ns("ns1.b.example.")
	complete := true
	answer := make(chan *AgentMsgResponse, 1)
	r.conf.InternalMp.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: roleB, UpdateType: "remote", DeliveredBy: roleB,
		OriginatingDistID: "b-1", OriginatingTime: time.Now(), CatchUp: &CatchUp{Request: "q1", Complete: &complete},
		Update: &ZoneUpdate{Zone: ZoneName(r.zone), AgentId: roleB, CatchUp: &CatchUp{Request: "q1", Complete: &complete},
			Operations: []core.RROperation{{Operation: "replace", RRtype: "NS", Records: []string{theirs}}}}, Response: answer}
	if a, ok := recvWithin(answer, 10*time.Second); !ok || a.Error {
		t.Fatalf("b's answer during the freeze: %+v", a)
	}
	dump := make(chan *SynchedDataCmdResponse, 1)
	r.conf.InternalMp.MsgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "dump-zonedatarepo", Zone: ZoneName(r.zone), Response: dump}
	d, ok := recvWithin(dump, 10*time.Second)
	if !ok {
		t.Fatal("the data engine did not answer the dump")
	}
	var names []string
	for _, info := range d.ZDR[ZoneName(r.zone)][roleB][dns.TypeNS] {
		if rr, err := dns.NewRR(info.RR); err == nil {
			names = append(names, rr.(*dns.NS).Ns)
		}
	}
	if !slices.Equal(names, []string{"ns1.b.example."}) {
		t.Errorf("b's NS in the data after its answer during the freeze: %v", names)
	}
}

// A sync held during the freeze is owed, and asked for at the release.
func TestTheOwedSyncIsAskedForWhenTheTransitionIsDone(t *testing.T) {
	r := newFreezeRig(t, "owed.freeze.example.")
	tr := newCatchUpTracker(roleA, nil, time.Minute)
	var asked []ZoneName
	tr.askSync = func(_ context.Context, zone ZoneName) owedResult { asked = append(asked, zone); return owedQueued }
	tr.owedApplies = func(context.Context, ZoneName) bool { return true }
	// caught up: the own state read, and b's complete answer in
	tr.zdr = r.zdr
	r.zdr.markOwnState(ZoneName(r.zone), true, "")
	tr.mu.Lock()
	tr.entryLocked(ZoneName(r.zone), roleB).Complete = true
	tr.mu.Unlock()
	r.conf.InternalMp.CatchUp = tr
	r.agree()
	if held, why := r.conf.syncHeld(r.zone, syncOther); !held || why != "agreeing on 42" {
		t.Fatalf("the leader's sync while frozen: held=%v %q", held, why)
	}
	if held, _ := r.conf.syncHeld(r.zone, syncDS); held {
		t.Error("the DS sync of a rollover was held")
	}
	tr.askAllOwed(context.Background(), false)
	if len(asked) != 0 {
		t.Fatalf("the owed sync was asked for during the freeze: %v", asked)
	}
	if _, kept := r.conf.freezeLines(r.zone); kept != "the sync with the parent" {
		t.Errorf("kept here: %q", kept)
	}
	r.done()
	if !slices.Equal(asked, []ZoneName{ZoneName(r.zone)}) {
		t.Errorf("at the release the sync asked for: %v", asked)
	}
}

// The operator is told that the edit is kept, and why: by the API.
func TestTheOperatorIsToldWhyTheEditIsKept(t *testing.T) {
	r := newFreezeRig(t, "told.freeze.example.")
	r.agree()
	go func() {
		u := <-r.conf.InternalMp.MsgQs.SynchedDataUpdate
		r.conf.applyLocalUpdate(context.Background(), r.zdr, u)
	}()
	resp := postAgent(t, r.conf, AgentMgmtPost{Command: "add-rr", Zone: ZoneName(r.zone), RRs: []string{r.ns("ns1.a.example.")}})
	if resp.Error || resp.Msg != fmt.Sprintf(`Adding 1 RR(s) for zone %q: kept until the transition is done (agreeing on 42)`, r.zone) {
		t.Errorf("the operator was told: %+v", resp)
	}
}

// postAgent is the agent's API for one command.
func postAgent(t *testing.T, conf *Config, amp AgentMgmtPost) AgentMgmtResponse {
	t.Helper()
	body, _ := json.Marshal(amp)
	w := httptest.NewRecorder()
	conf.APIagent(t.Context(), nil, nil)(w, httptest.NewRequest(http.MethodPost, "/api/v1/agent", bytes.NewReader(body)))
	var resp AgentMgmtResponse
	if err := json.NewDecoder(w.Result().Body).Decode(&resp); err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	return resp
}

// The status says why the zone is frozen and whom the agreement waits for,
// and what this agent keeps.
func TestTheFreezeIsShownInTheStatus(t *testing.T) {
	r := newFreezeRig(t, "status.freeze.example.")
	if frozen, kept := r.conf.freezeLines(r.zone); frozen != "" || kept != "" {
		t.Fatalf("a steady zone: %q, %q", frozen, kept)
	}
	r.agree()
	r.edit("ns1.a.example.")
	r.edit("ns2.a.example.")
	r.conf.InternalMp.MPTransport.stamps = newStampTable(roleA, r.store, 1, true, nil)
	frozen, kept := r.conf.freezeLines(r.zone)
	if frozen != "agreeing on 42, waiting for a.role.example. (no hold yet), b.role.example. (not heard)" {
		t.Errorf("frozen: %q", frozen)
	}
	if kept != "2 changes of this provider's own" {
		t.Errorf("kept here: %q", kept)
	}
	// b tells active 41 and agrees on 42 with its signer's hold
	st := tells(r.n, r.v)
	st.Agreeing, st.AgreeingDigest, st.Hold = r.v.Serial, r.v.Digest(), true
	r.conf.InternalMp.MPTransport.stamps.note(told(roleB, 1, 1, InstrStamp{}), roleB, transport.MechanismDNS)
	r.conf.InternalMp.MPTransport.stamps.note(&GossipMessage{GroupHash: stampGroupHash, Members: map[string]*MemberState{
		roleB: {Identity: roleB, Timestamp: time.Now(), Epoch: 1, Seq: 2, Crypto: true, Instr: map[string]InstrStamp{r.zone: st}}}}, roleB, transport.MechanismDNS)
	if frozen, _ := r.conf.freezeLines(r.zone); frozen != "agreeing on 42, waiting for a.role.example. (no hold yet)" {
		t.Errorf("frozen, with b's telling: %q", frozen)
	}
}

// The signer keeps its agent's hold, and its inventory, pushed then and
// at every later push, says so. The agent records it.
func TestTheSignerConfirmsTheHoldInItsInventory(t *testing.T) {
	const zone = "confirm.freeze.example."
	conf := &Config{Config: &tdns.Config{}}
	holds, err := loadSignerHolds(nil)
	if err != nil {
		t.Fatal(err)
	}
	conf.InternalMp.SignerHolds = holds
	conf.signerHold(zone, true)
	if !holds.held(zone) {
		t.Fatal("the signer did not keep the hold")
	}
	req := inventoryRequest("signer.a.example.", zone, nil, true, nil, inventoryMarks{hold: holds.held(zone)})
	msg, err := keystateAppMessage(req, roleA)
	if err != nil {
		t.Fatal(err)
	}
	var p DnsKeystatePayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil || !p.Hold || p.Signal != "inventory" {
		t.Fatalf("the inventory on the wire: %+v %v", p, err)
	}
	conf.signerHold(zone, false)
	if holds.held(zone) {
		t.Error("the signer kept the hold its agent let go")
	}
}

// The stamp says Hold once the signer holds the hand-over with the hold and
// an inventory with the hold has arrived after the agent came to hold its
// newest serial; not before, and not from an older inventory.
func TestTheStampSaysHoldOnlyAfterTheConfirmation(t *testing.T) {
	r := newFreezeRig(t, "stamp.freeze.example.")
	r.withSigner()
	mpzd, ok := Zones.Get(r.zone)
	if !ok {
		t.Fatal("no zone")
	}
	mpzd.SetLastKeyInventory(&KeyInventorySnapshot{Zone: r.zone, Hold: true, Received: time.Now()})
	time.Sleep(10 * time.Millisecond)
	r.agree()
	if r.conf.holdConfirmed(r.zone) {
		t.Error("an inventory from before the newest serial was held confirms the hold")
	}
	tbl := newStampTable(roleA, r.store, 1, true, nil)
	tbl.hold = r.conf.holdConfirmed
	if st, _ := tbl.ownStamp(r.zone); st.Hold {
		t.Error("the stamp says Hold before the confirmation")
	}
	r.confirm(false)
	if r.conf.holdConfirmed(r.zone) {
		t.Error("an inventory without the hold confirms it")
	}
	r.confirm(true)
	if st, _ := tbl.ownStamp(r.zone); !st.Hold {
		t.Error("the stamp does not say Hold after the confirmation")
	}
	if ms := tbl.messageStamp(r.zone); ms == nil || !ms.Hold {
		t.Error("a message's stamp does not say Hold after the confirmation")
	}
}

// The agent hands its signer the hold when the zone is frozen, and again
// while its inventory says it holds otherwise: the hold is a field of the
// hand-over, which the agent hands until the signer holds it (plan S11).
func TestTheHoldIsToldAgainWhenTheInventorySaysOtherwise(t *testing.T) {
	r := newFreezeRig(t, "retell.freeze.example.")
	q := r.withSigner()
	r.agree()
	// the hand-over that changed, and the signer asked to confirm it
	if h := lastHanded(t, signerSent(t, q, 2)); !h.Sets.Hold {
		t.Fatal("the hold was not handed when the zone froze")
	}
	tr := r.conf.InternalMp.SignerHandover
	age := func() {
		tr.mu.Lock()
		tr.zones[handoverKey(r.zone)].flightAt = time.Now().Add(-2 * handoverResend)
		tr.mu.Unlock()
	}
	// an inventory that says the signer holds the zone without the hold
	without := *r.wanted()
	without.Sets.Hold = false
	tr.learned(r.zone, &without)
	age()
	tr.tick()
	if h := lastHanded(t, signerSent(t, q, 1)); !h.Sets.Hold {
		t.Error("an inventory without the hold did not have it handed again")
	}
	// an inventory that agrees has nothing handed
	r.confirm(true)
	age()
	tr.tick()
	time.Sleep(50 * time.Millisecond)
	if got := q.take(); len(got) != 0 {
		t.Errorf("the signer holds the hold by its inventory, and %d more hand-overs went", len(got))
	}
}

// The hold is confirmed for the serial agreed on (the external review of
// #301): a refused serial above it leaves a confirmed hold confirmed; a
// newer serial that becomes the one agreed on has the signer say again what
// it holds, and counts only an inventory that arrives after it.
func TestTheHoldIsConfirmedForTheSerialAgreedOn(t *testing.T) {
	r := newFreezeRig(t, "agreed.freeze.example.")
	q := r.withSigner()
	r.agree()
	signerSent(t, q, 2)
	time.Sleep(5 * time.Millisecond)
	r.confirm(true)
	if !r.conf.holdConfirmed(r.zone) {
		t.Fatal("the hold is not confirmed by an inventory after the serial agreed on")
	}

	// a refused 43: b's record removed while b has a role
	time.Sleep(5 * time.Millisecond)
	r.store.Note(r.zone, jAt(t, 43, `servers="a,b" nsmgmt="agent"`, freezeRecords[0], freezeRecords[2]), nil)
	if st := r.store.Status(r.zone); st.Newest.Serial != 43 || st.Agreeing.Serial != 42 {
		t.Fatalf("after the refused 43: newest %v, agreeing %v", st.Newest, st.Agreeing)
	}
	if !r.conf.holdConfirmed(r.zone) {
		t.Error("a refused serial above the one agreed on made the confirmed hold stale")
	}
	time.Sleep(50 * time.Millisecond)
	if got := q.take(); len(got) != 0 {
		t.Errorf("a refused serial had the hold handed again: %d hand-overs", len(got))
	}

	// an accepted 44 becomes the serial agreed on
	time.Sleep(5 * time.Millisecond)
	r.store.Note(r.zone, freezeAt(t, 44, "w", "a,b", ""), nil)
	if st := r.store.Status(r.zone); st.Agreeing.Serial != 44 {
		t.Fatalf("after the accepted 44: agreeing %v", st.Agreeing)
	}
	if r.conf.holdConfirmed(r.zone) {
		t.Error("an inventory from before the new serial agreed on confirms the hold")
	}
	if h := lastHanded(t, signerSent(t, q, 1)); !h.Sets.Hold {
		t.Error("the hold was not handed again when the serial agreed on moved")
	}
	time.Sleep(5 * time.Millisecond)
	r.confirm(true)
	if !r.conf.holdConfirmed(r.zone) {
		t.Error("an inventory after the new serial agreed on does not confirm the hold")
	}
}

// An edit made after the thaw, but before the release has run, goes after
// the owed edits: it was made over them, and the release does not undo it
// (CodeRabbit's review of ff9348d).
func TestAnEditAfterTheThawGoesAfterTheOwedEdits(t *testing.T) {
	r := newFreezeRig(t, "after.freeze.example.")
	r.agree()
	r.edit("ns1.a.example.")
	// the thaw and "done", with the release not run yet (its command waits
	// in the engine's queue)
	if err := r.store.Activate(r.zone, Thaw{From: sd(r.n), To: sd(r.v)}); err != nil {
		t.Fatal(err)
	}
	if err := r.store.Done(r.zone); err != nil {
		t.Fatal(err)
	}
	// the operator's next edit, made over the owed one
	if a := r.edit("ns1.a.example.", "ns2.a.example."); a.Error || a.Kept != "" {
		t.Fatalf("the edit after the thaw: %+v", a)
	}
	if owed := r.conf.InternalMp.Kept.entries(r.zone, listOwed); len(owed) != 0 {
		t.Errorf("%d entries still owed after an edit of the thawed zone", len(owed))
	}
	r.conf.instrDone(context.Background(), r.zdr, ZoneName(r.zone))
	if got := r.ownNS(); !slices.Equal(got, []string{"ns1.a.example.", "ns2.a.example."}) {
		t.Errorf("the data after the release: %v, want the later edit's set", got)
	}
}

// A delete of a record an owed edit added is this agent's to make: it is
// kept too, not refused as not owned (cubic's review of ff9348d).
func TestADeleteOfAnOwedAddIsKept(t *testing.T) {
	r := newFreezeRig(t, "delete.freeze.example.")
	local := func(ops []core.RROperation, rrs ...dns.RR) *AgentMsgResponse {
		t.Helper()
		answer := make(chan *AgentMsgResponse, 1)
		r.conf.applyLocalUpdate(context.Background(), r.zdr, &SynchedDataUpdate{Zone: ZoneName(r.zone), AgentId: roleA, UpdateType: "local",
			Update: &ZoneUpdate{Zone: ZoneName(r.zone), AgentId: roleA, RRs: rrs, Operations: ops}, Response: answer})
		return <-answer
	}
	rr := func(name string, class uint16) dns.RR {
		x, _ := dns.NewRR(r.ns(name))
		x.Header().Class = class
		return x
	}
	replace := func(names ...string) []core.RROperation {
		var recs []string
		for _, n := range names {
			recs = append(recs, r.ns(n))
		}
		return []core.RROperation{{Operation: "replace", RRtype: "NS", Records: recs}}
	}
	// ns1 in the data before the freeze, ns2 added during it
	if a := local(replace("ns1.a.example."), rr("ns1.a.example.", dns.ClassINET)); a.Error {
		t.Fatalf("the edit before the freeze: %+v", a)
	}
	r.agree()
	if a := local(replace("ns1.a.example.", "ns2.a.example."), rr("ns2.a.example.", dns.ClassINET)); a.Error || a.Kept == "" {
		t.Fatalf("the add during the freeze: %+v", a)
	}
	if a := local(replace("ns1.a.example."), rr("ns2.a.example.", dns.ClassNONE)); a.Error || a.Kept == "" {
		t.Errorf("the delete of the owed add: %+v", a)
	}
	// a record neither the data nor the owed list holds is refused, as before
	if a := local(replace("ns1.a.example."), rr("ns9.a.example.", dns.ClassNONE)); !a.Error || !strings.Contains(a.ErrorMsg, "not owned") {
		t.Errorf("a delete of a record nobody holds: %+v", a)
	}
}

// A frozen zone that leaves the configuration ends its freeze: the signer
// lets the hold go, and what the zone owed is dropped, not released into a
// zone that is gone (cubic's review of ff9348d).
func TestAFrozenZoneThatLeavesTheConfigurationLetsTheHoldGo(t *testing.T) {
	r := newFreezeRig(t, "prune.freeze.example.")
	q := r.withSigner()
	r.agree()
	r.edit("ns1.a.example.")
	// a zone leaves tdns's zones before the store prunes it (config.go):
	// the agent hands it nothing more, but the signer lets the hold go
	mpzd, _ := Zones.Get(r.zone)
	mpzd.Ready = false
	r.store.Prune(func(string) bool { return false })
	mpzd.Ready = true
	waitUntil(t, "the signer was not handed the zone without the hold after it left the configuration", func() bool {
		q.mu.Lock()
		defer q.mu.Unlock()
		n := len(q.msgs)
		return n > 0 && q.msgs[n-1].update.Acting != nil && !q.msgs[n-1].update.Acting.Sets.Hold
	})
	before := r.sent()
	r.conf.instrDone(context.Background(), r.zdr, ZoneName(r.zone))
	if owed := r.conf.InternalMp.Kept.entries(r.zone, listOwed); len(owed) != 0 {
		t.Errorf("%d entries owed after the zone left", len(owed))
	}
	if after := r.sent(); !maps.Equal(before, after) {
		t.Errorf("a kept edit of a zone that left was sent: %v, before %v", after, before)
	}
}

// An inventory that carries the hold confirms it only when it came after
// the agent last had the signer say what it holds: one from before does
// not (cubic's review of ff9348d).
func TestAnInventoryBeforeTheHoldWasToldDoesNotConfirmIt(t *testing.T) {
	r := newFreezeRig(t, "stale.hold.freeze.example.")
	r.withSigner()
	r.agree()
	time.Sleep(5 * time.Millisecond)
	r.confirm(true)
	if !r.conf.holdConfirmed(r.zone) {
		t.Fatal("an inventory after the hold was handed does not confirm it")
	}
	r.conf.InternalMp.SignerHandover.again(r.zone)
	if r.conf.holdConfirmed(r.zone) {
		t.Error("an inventory from before the hold was handed again confirms it")
	}
}
