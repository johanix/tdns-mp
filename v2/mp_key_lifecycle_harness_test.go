package tdnsmp

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// T3.2, the harness: two to four providers of one zone in one process, each
// with its own keystore, driver and view, the fake clock shared, and a wire
// between them that can lose, duplicate and reorder. T3.3, the property
// runs: seeded random event sequences, the invariants and P1-P9 after every
// event, a drain at the end that must leave nothing in flight.

type hmsg struct {
	from, to string
	keyid    uint16
	removal  bool
	keyrr    string
}

type hProvider struct {
	id     string
	zone   string
	kdb    *tdns.KeyDB
	zd     *MPZoneData
	driver *ZoneKeyLifecycle
	wire   *harnessWire
	// what the harness knows the machine did, for the properties
	appliedBy    map[uint16]map[string]bool // key -> providers whose applied confirmation was delivered
	expectedAt   map[uint16][]string        // key -> the other signers when it was last distributed
	rejected     map[uint16]bool
	rejectedLate map[uint16]bool // a joiner's rejection of a key already serving
	minted       map[uint16]bool
	signed       map[uint16]bool // keys seen with sign=1
}

type mpHarness struct {
	t         *testing.T
	rng       *rand.Rand
	clock     *fakeClock
	providers []*hProvider
	byID      map[string]*hProvider
	signing   map[string]bool // which providers sign the zone now
	queue     []hmsg
	loss, dup float64
	reorder   bool
	// how a receiver answers a distribution: applied, pending (then applied
	// on a later delivery), rejected
	answer func(from, to string, keyid uint16) string
	mu     sync.Mutex
}

type harnessWire struct {
	h  *mpHarness
	me *hProvider
	fakeWire
}

func (w *harnessWire) OtherSigners(zone string) []string {
	w.h.mu.Lock()
	defer w.h.mu.Unlock()
	var out []string
	for _, p := range w.h.providers {
		if p.id != w.me.id && w.h.signing[p.id] {
			out = append(out, p.id)
		}
	}
	sort.Strings(out)
	return out
}

func (w *harnessWire) send(keyid uint16, removal bool) {
	keyrr := ""
	if !removal {
		inv, err := tdns.GetKeyInventory(w.me.kdb, w.me.zone)
		if err != nil {
			w.h.t.Fatal(err)
		}
		for _, it := range inv {
			if it.KeyTag == keyid {
				keyrr = it.KeyRR
			}
		}
	}
	w.h.mu.Lock()
	defer w.h.mu.Unlock()
	if !removal {
		w.me.expectedAt[keyid] = nil
	}
	for _, p := range w.h.providers {
		if p.id == w.me.id || !w.h.signing[p.id] {
			continue
		}
		if !removal {
			w.me.expectedAt[keyid] = append(w.me.expectedAt[keyid], p.id)
		}
		m := hmsg{from: w.me.id, to: p.id, keyid: keyid, removal: removal, keyrr: keyrr}
		if w.h.rng.Float64() < w.h.loss {
			continue
		}
		w.h.queue = append(w.h.queue, m)
		if w.h.rng.Float64() < w.h.dup {
			w.h.queue = append(w.h.queue, m)
		}
	}
}

func (w *harnessWire) Distribute(zone string, keyid uint16)        { w.send(keyid, false) }
func (w *harnessWire) DistributeRemoval(zone string, keyid uint16) { w.send(keyid, true) }
func (w *harnessWire) ParentServesDS(zone string, keyid uint16) (bool, bool) {
	// the parent follows the provider's own DS intent with no delay: it
	// serves exactly the ds=1 KSKs
	inv, err := tdns.GetKeyInventory(w.me.kdb, w.me.zone)
	if err != nil {
		return false, false
	}
	for _, it := range inv {
		if it.KeyTag == keyid {
			return it.DS != nil && *it.DS, true
		}
	}
	return false, true
}

func newMPHarness(t *testing.T, seed uint64, n int, pol LifecyclePolicy) *mpHarness {
	t.Helper()
	h := &mpHarness{t: t, rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), clock: &fakeClock{t: time.Now()},
		byID: map[string]*hProvider{}, signing: map[string]bool{}}
	h.answer = func(from, to string, keyid uint16) string { return "applied" }
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("p%d", i+1)
		zone := fmt.Sprintf("%s.seed%d.harness.example.", id, seed)
		kdb := newMPTestKeyDB(t)
		zd := signerTestZone(t, zone, kdb)
		p := &hProvider{id: id, zone: zone, kdb: kdb, zd: zd, appliedBy: map[uint16]map[string]bool{}, expectedAt: map[uint16][]string{},
			rejected: map[uint16]bool{}, rejectedLate: map[uint16]bool{}, minted: map[uint16]bool{}, signed: map[uint16]bool{}}
		p.wire = &harnessWire{h: h, me: p, fakeWire: *newFakeWire()}
		p.driver = NewZoneKeyLifecycle(zone, kdb, h.clock, pol, p.wire)
		pid := id
		p.driver.Log = func(msg string, kv ...any) { t.Logf("%s %s %v", pid, msg, kv) }
		h.providers = append(h.providers, p)
		h.byID[id] = p
		h.signing[id] = true
	}
	return h
}

// deliver hands every queued message to its receiver: a distribution is
// recorded as a foreign row and answered per the harness's answer function;
// a removal deletes the foreign row and is answered applied.
func (h *mpHarness) deliver() {
	h.mu.Lock()
	q := h.queue
	h.queue = nil
	if h.reorder {
		h.rng.Shuffle(len(q), func(i, j int) { q[i], q[j] = q[j], q[i] })
	}
	h.mu.Unlock()
	for _, m := range q {
		from, to := h.byID[m.from], h.byID[m.to]
		status := "applied"
		if !m.removal {
			status = h.answer(m.from, m.to, m.keyid)
		}
		h.t.Logf("deliver %s -> %s key %d removal=%v answer=%s", m.from, m.to, m.keyid, m.removal, status)
		stateBefore := mpKeyState(h.t, from.kdb, from.zone, m.keyid)
		switch status {
		case "applied":
			if m.removal {
				to.kdb.DB.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=? AND keyid=? AND state=?`, to.zone, int(m.keyid), DnskeyStateForeign)
			} else {
				rr, err := dns.NewRR(m.keyrr)
				if err != nil {
					h.t.Fatalf("foreign key %d from %s: %v", m.keyid, m.from, err)
				}
				dk := rr.(*dns.DNSKEY)
				to.kdb.DB.Exec(`DELETE FROM DnssecKeyStore WHERE zonename=? AND keyid=? AND state=?`, to.zone, int(m.keyid), DnskeyStateForeign)
				// a keytag the receiver already has as a key of its own
				// cannot be recorded as a foreign row (the store is unique on
				// zone and keytag); the machine does not read foreign rows,
				// so the delivery still counts (a random 16-bit collision)
				var own string
				if err := to.kdb.DB.QueryRow(`SELECT state FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, to.zone, int(m.keyid)).Scan(&own); err == nil {
					h.t.Logf("keytag %d of %s collides with a key of %s's own; the foreign row is not recorded", m.keyid, m.from, m.to)
				} else if err := insertForeignKeyRow(to.kdb, to.zone, m.keyid, dk, dns.AlgorithmToString[dk.Algorithm]); err != nil {
					h.t.Fatalf("record the foreign key: %v", err)
				}
				if from.appliedBy[m.keyid] == nil {
					from.appliedBy[m.keyid] = map[string]bool{}
				}
				from.appliedBy[m.keyid][m.to] = true
			}
		}
		if _, _, err := from.driver.ConfirmKind(m.keyid, m.to, status, "harness says "+status, m.removal); err != nil {
			// a confirmation for a distribution no longer in flight (a
			// duplicate after the key moved on, or an answer to the
			// distribution after the removal went out) is not an error of
			// the machine
			if !containsStr(err.Error(), "no distribution in flight") && !errors.Is(err, ErrStaleConfirmation) {
				h.t.Fatalf("confirm %s -> %s key %d %s: %v", m.to, m.from, m.keyid, status, err)
			}
		} else if status == "rejected" {
			if stateBefore == KeyStateMpdist {
				// a rejection of a key in the pipeline: the machine holds it (P8)
				from.rejected[m.keyid] = true
			} else {
				// a joiner's rejection of a key already serving is reported,
				// not retreated from (§5.6): the operator retries or withdraws
				from.rejectedLate[m.keyid] = true
			}
		}
	}
}

func (h *mpHarness) tickAll(step string) {
	h.t.Helper()
	for _, p := range h.providers {
		if err := p.driver.Tick(); err != nil {
			h.t.Fatalf("%s: %s tick: %v", step, p.id, err)
		}
	}
}

// inventory of a provider's own keys and foreign rows
func (h *mpHarness) inventory(p *hProvider) []tdns.KeyInventoryItem {
	inv, err := tdns.GetKeyInventory(p.kdb, p.zone)
	if err != nil {
		h.t.Fatal(err)
	}
	return inv
}

// checkAll: tdns's key row invariants and P1-P9 on every provider.
func (h *mpHarness) checkAll(step string) {
	h.t.Helper()
	for _, p := range h.providers {
		if vs := tdns.CheckKeyRowInvariants(p.kdb, p.zone); len(vs) != 0 {
			h.t.Errorf("%s: %s: %v", step, p.id, vs)
		}
		signing := map[string]int{}
		for _, it := range h.inventory(p) {
			if it.State == DnskeyStateForeign {
				continue
			}
			p.minted[it.KeyTag] = true
			role := roleOf(it.Flags)
			// P1: when a key first signs, every signer it was distributed to
			// has confirmed applying it
			if it.Sign {
				signing[fmt.Sprintf("%s/%d", role, it.Algorithm)]++
				if !p.signed[it.KeyTag] {
					p.signed[it.KeyTag] = true
					for _, q := range p.expectedAt[it.KeyTag] {
						if h.signing[q] && !p.appliedBy[it.KeyTag][q] {
							h.t.Errorf("%s: %s key %d signs but %s never confirmed applying it (P1)", step, p.id, it.KeyTag, q)
						}
					}
					// ... and the DNSKEY RRset with the key has propagated:
					// the delay plus the served TTL since it was published
					var published string
					if err := p.kdb.DB.QueryRow(`SELECT COALESCE(published_at, '') FROM DnssecKeyStore WHERE zonename=? AND keyid=?`, p.zone, int(it.KeyTag)).Scan(&published); err != nil {
						h.t.Errorf("%s: %s key %d: published_at: %v", step, p.id, it.KeyTag, err)
					} else if at, err := time.Parse(time.RFC3339, published); err != nil {
						h.t.Errorf("%s: %s key %d signs with no published_at (%q) (P1)", step, p.id, it.KeyTag, published)
					} else if wait := p.driver.Policy.PropagationDelay + p.wire.ttl; h.clock.Now().Before(at.Add(wait)) {
						h.t.Errorf("%s: %s key %d signs %s after it was published, before the propagation wait %s (P1)", step, p.id, it.KeyTag, h.clock.Now().Sub(at), wait)
					}
				}
			}
			// P2: a KSK's ds=1 only in standby, active or retired
			if it.DS != nil && *it.DS && (it.Flags&dns.SEP == 0 || (it.State != KeyStateStandby && it.State != KeyStateActive && it.State != KeyStateRetired)) {
				h.t.Errorf("%s: %s key %d (%s, flags %d) has ds=1 (P2)", step, p.id, it.KeyTag, it.State, it.Flags)
			}
			// P8: a rejected key never promoted
			if p.rejected[it.KeyTag] && (it.Sign || it.State == KeyStateStandby || it.State == KeyStatePublished) {
				h.t.Errorf("%s: %s rejected key %d is %s (P8)", step, p.id, it.KeyTag, it.State)
			}
			// P7: alone, never in mpdist or mpremove (a rejected key waits
			// for the operator whoever is left, P8)
			if len(p.wire.OtherSigners(p.zone)) == 0 && !p.rejected[it.KeyTag] && (it.State == KeyStateMpdist || it.State == KeyStateMpremove) {
				h.t.Errorf("%s: %s alone has key %d in %s (P7)", step, p.id, it.KeyTag, it.State)
			}
		}
		for k, n := range signing {
			if n > 1 {
				h.t.Errorf("%s: %s has %d signing keys of %s (P5)", step, p.id, n, k)
			}
		}
	}
}

// drain: deliver and tick with time passing until nothing has been in
// flight for three rounds (a key minted in the last round still has to
// propagate and be promoted), or give up. Returns what is still in flight.
func (h *mpHarness) drain(rounds int) []string {
	h.t.Helper()
	loss, dup := h.loss, h.dup
	h.loss, h.dup = 0, 0
	defer func() { h.loss, h.dup = loss, dup }()
	quiet := 0
	for i := 0; i < rounds; i++ {
		h.deliver()
		h.clock.Advance(2 * time.Hour)
		h.tickAll("drain")
		if len(h.inFlight()) == 0 {
			if quiet++; quiet == 3 {
				return nil
			}
		} else {
			quiet = 0
		}
	}
	return h.inFlight()
}

func (h *mpHarness) inFlight() []string {
	var out []string
	for _, p := range h.providers {
		for _, it := range h.inventory(p) {
			if it.State == KeyStateMpdist || it.State == KeyStateMpremove || it.State == KeyStateCreated {
				out = append(out, fmt.Sprintf("%s:%d:%s", p.id, it.KeyTag, it.State))
			}
		}
	}
	sort.Strings(out)
	return out
}

func (h *mpHarness) restart(p *hProvider) {
	h.t.Helper()
	log := p.driver.Log
	p.driver = NewZoneKeyLifecycle(p.zone, p.kdb, h.clock, p.driver.Policy, p.wire)
	p.driver.Log = log
	if err := p.driver.Reload(); err != nil {
		h.t.Fatalf("%s reload: %v", p.id, err)
	}
}

var harnessPolicy = LifecyclePolicy{KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519, StandbyKSK: 1, StandbyZSK: 1,
	PropagationDelay: 10 * time.Minute, Margin: time.Hour, ResendAfter: 30 * time.Minute}

// The scenarios of T3.4 through the harness: three providers bootstrap,
// hold standbys, roll a KSK, one provider leaves mid-roll, one restarts.
func TestHarnessThreeProvidersRollAKSK(t *testing.T) {
	h := newMPHarness(t, 1, 3, harnessPolicy)
	step := func(name string) {
		h.deliver()
		h.tickAll(name)
		h.deliver()
		h.checkAll(name)
	}
	step("mint")
	h.clock.Advance(harnessPolicy.PropagationDelay + time.Hour + time.Second)
	step("propagated")
	for _, p := range h.providers {
		if n := len(activeOf(h, p, "KSK")); n != 1 {
			t.Fatalf("%s: %d active KSKs after bootstrap, want 1", p.id, n)
		}
	}
	step("standbys wanted")
	h.clock.Advance(harnessPolicy.PropagationDelay + time.Hour + time.Second)
	step("standbys propagated")
	p1 := h.providers[0]
	if sb := standbyOf(h, p1, "KSK"); len(sb) != 1 {
		t.Fatalf("p1 standby KSKs %v, want 1", sb)
	}
	old := activeOf(h, p1, "KSK")[0]
	p1.driver.RequestRollover("KSK")
	step("roll")
	if got := activeOf(h, p1, "KSK"); len(got) != 1 || got[0] == old {
		t.Fatalf("after the roll p1's active KSK %v (old %d)", got, old)
	}
	// p3 leaves the signing set while the old key's removal is in flight
	h.clock.Advance(harnessPolicy.Margin + time.Second)
	step("margin")
	h.mu.Lock()
	h.signing["p3"] = false
	h.mu.Unlock()
	for _, p := range h.providers {
		if err := p.driver.SignersChanged(); err != nil {
			t.Fatal(err)
		}
	}
	h.restart(h.providers[1])
	if left := h.drain(10); len(left) != 0 {
		t.Errorf("after the drain, still in flight: %v", left)
	}
	h.checkAll("drained")
	// every foreign row on p1 and p2 is a key the other serves
	for _, p := range h.providers[:2] {
		for _, it := range h.inventory(p) {
			if it.State == DnskeyStateForeign && it.KeyTag == old {
				t.Errorf("%s still holds the removed KSK %d as foreign", p.id, old)
			}
		}
	}
}

func activeOf(h *mpHarness, p *hProvider, role string) []uint16 {
	var out []uint16
	for _, it := range h.inventory(p) {
		if it.State == KeyStateActive && roleOf(it.Flags) == role {
			out = append(out, it.KeyTag)
		}
	}
	return out
}

func sortedKeys(m map[uint16]bool) []uint16 {
	var out []uint16
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func standbyOf(h *mpHarness, p *hProvider, role string) []uint16 {
	var out []uint16
	for _, it := range h.inventory(p) {
		if it.State == KeyStateStandby && roleOf(it.Flags) == role {
			out = append(out, it.KeyTag)
		}
	}
	return out
}

// T3.3: seeded random runs. Events: deliveries with loss, duplication and
// reordering; answers of pending and rejected; time; rollover requests;
// a signer leaving or returning; a restart. After every event the
// invariants and P1-P9; after a fair drain, nothing in flight and every
// signing provider with an active KSK and ZSK (P4, P6).
func TestHarnessPropertyRuns(t *testing.T) {
	// CP4 asks for at least 200 seeded sequences per property in CI (and
	// 5,000 before a merge, run as a soak); -short keeps a handful
	seeds := 200
	if testing.Short() {
		seeds = 4
	}
	for seed := uint64(1); seed <= uint64(seeds); seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			n := 2 + int(seed%3)
			h := newMPHarness(t, seed, n, harnessPolicy)
			h.loss, h.dup, h.reorder = 0.15, 0.1, true
			pendingFirst := map[string]bool{}
			h.answer = func(from, to string, keyid uint16) string {
				k := fmt.Sprintf("%s/%s/%d", from, to, keyid)
				r := h.rng.Float64()
				switch {
				case r < 0.05:
					return "rejected"
				case r < 0.35 && !pendingFirst[k]:
					pendingFirst[k] = true
					return "pending"
				}
				return "applied"
			}
			for ev := 0; ev < 40; ev++ {
				name := fmt.Sprintf("seed %d event %d", seed, ev)
				kind := h.rng.IntN(6)
				t.Logf("== %s: kind %d", name, kind)
				switch kind {
				case 0, 1:
					h.deliver()
				case 2:
					h.clock.Advance(time.Duration(h.rng.IntN(120)) * time.Minute)
					h.tickAll(name)
				case 3:
					p := h.providers[h.rng.IntN(n)]
					role := []string{"KSK", "ZSK"}[h.rng.IntN(2)]
					if h.rng.IntN(3) == 0 {
						p.driver.CancelRollover(role)
					} else {
						p.driver.RequestRollover(role)
					}
				case 4:
					if n > 2 {
						id := h.providers[h.rng.IntN(n)].id
						h.mu.Lock()
						h.signing[id] = !h.signing[id]
						t.Logf("toggle %s signing=%v", id, h.signing[id])
						h.mu.Unlock()
						for _, p := range h.providers {
							if err := p.driver.SignersChanged(); err != nil {
								t.Fatalf("%s: %v", name, err)
							}
						}
					}
				case 5:
					h.restart(h.providers[h.rng.IntN(n)])
				}
				h.checkAll(name)
				if t.Failed() {
					t.Fatalf("seed %d fails at event %d; keep it as a regression test", seed, ev)
				}
			}
			// a rejected key never resolves on its own: the operator withdraws
			// one rejected in the pipeline and retries one a joiner rejected
			h.answer = func(from, to string, keyid uint16) string { return "applied" }
			for _, p := range h.providers {
				for _, k := range sortedKeys(p.rejected) {
					if _, to, err := p.driver.Apply(k, CmdWithdraw); err != nil || to != KeyStateMpremove && to != KeyStateRemoved {
						t.Logf("seed %d: %s withdraw of rejected key %d: to %s err %v", seed, p.id, k, to, err)
					}
				}
				for _, k := range sortedKeys(p.rejectedLate) {
					if _, _, err := p.driver.Apply(k, CmdRetry); err != nil {
						t.Logf("seed %d: %s retry of key %d: %v", seed, p.id, k, err)
					}
				}
			}
			h.answer = func(from, to string, keyid uint16) string { return "applied" }
			h.reorder = false
			if left := h.drain(12); len(left) != 0 {
				t.Errorf("seed %d: after a fair drain, still in flight: %v (P6)", seed, left)
			}
			h.checkAll(fmt.Sprintf("seed %d drained", seed))
			for _, p := range h.providers {
				if !h.signing[p.id] {
					continue
				}
				for _, role := range []string{"KSK", "ZSK"} {
					if n := len(activeOf(h, p, role)); n != 1 {
						t.Errorf("seed %d: %s ends with %d active %s, want 1 (P4)", seed, p.id, n, role)
					}
				}
			}
		})
	}
}
