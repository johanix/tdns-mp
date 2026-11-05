/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"crypto"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	okBetaToCharlie = `3600 IN HSYNC3 ON beta agent.beta.example. charlie`
	okCDS           = `3600 IN CDS 12345 15 2 ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789`
	okCDSRolled     = `3600 IN CDS 54321 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF`
	okCDNSKEY       = `3600 IN CDNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=`
)

func upstreamStep(id string) InstrStep {
	return InstrStep{Number: 1, Of: 2, Digest: "d1", Taken: []string{upstreamKey + id}}
}

// holdingUpstreamStep gives the rig's agent a store, on no disk, with the zone
// active and the upstream's step of its own provider held: what the
// nameservers served at the first check goes with that step.
func (r *servingRig) holdingUpstreamStep(t *testing.T) InstrStep {
	t.Helper()
	in := instructionsFor(ZoneName(r.zone))
	store := loadStore(t, nil)
	knownAs(t, store, r.zone, in)
	raw, digest, err := stepDigest(rolesFor(in, in, 0))
	if err != nil {
		t.Fatal(err)
	}
	step := InstrStep{Number: 1, Of: 2, Sets: raw, Digest: digest, Taken: []string{upstreamKey + srNewcomer}}
	if err := store.setStep(r.zone, sd(in), step, nil); err != nil {
		t.Fatal(err)
	}
	r.conf.InternalMp.Instructions = store
	return step
}

// An upstream (design 5.6): the judge agrees it, and its step, a role
// change's that changes no set, comes before the last. Only a provider whose
// servers serve under the sets held and under V has one: one that enters
// servers= has its server role's step, a signer's servers serve its own
// signer's copy, and with no from nothing says what moved. At the provider's
// own agent the step is held only once its nameservers serve the zone from
// the new upstream, at the serial they served or later: signed by the old
// upstream's key, or below that serial though above the zone's copy, it
// waits. Another agent's part of it is its parts alone.
func TestAnUpstreamChangeIsAStepThatWaitsForTheServers(t *testing.T) {
	param := `servers="alpha,beta,charlie" signers="alpha,charlie"`
	from := jAt(t, 41, param, jAlpha, jBeta, jCharlie)
	to := jAt(t, 42, param, jAlpha, okBetaToCharlie, jCharlie)
	if rs := judgeTransition(from, to); len(rs) > 0 {
		t.Fatalf("the upstream is refused: %v", rs)
	}
	plan := planSteps(planView{from: from, to: to, held: rolesFor(from, from, 0)})
	if len(plan) != 2 || plan[0].key != upstreamKey+"agent.beta.example." || plan[0].kind != stepRoleChange || plan[0].sets != nil || plan[0].provider != "agent.beta.example." {
		t.Fatalf("the steps: %+v", plan)
	}
	for name, p := range map[string]planView{
		"no from":          {to: to, held: rolesFor(to, to, 0)},
		"entering servers": {from: from, to: to, held: rolesFor(jAt(t, 41, `servers="alpha,charlie" signers="alpha,charlie"`, jAlpha, jBeta, jCharlie), nil, 0)},
		"a signer": {from: jAt(t, 41, `servers="alpha,beta" signers="alpha,beta,charlie"`, jAlpha, jBeta, jCharlie),
			to:   jAt(t, 42, `servers="alpha,beta" signers="alpha,beta,charlie"`, jAlpha, okBetaToCharlie, jCharlie),
			held: rolesFor(jAt(t, 41, `servers="alpha,beta" signers="alpha,beta,charlie"`, jAlpha, jBeta, jCharlie), nil, 0)},
	} {
		if got := planSteps(p); slices.ContainsFunc(got, func(st plannedStep) bool { return strings.HasPrefix(st.key, upstreamKey) }) {
			t.Errorf("%s: an upstream's step: %+v", name, got)
		}
	}

	r := newServingRig(t, "move.upstream.example.", srNewcomer)
	step := r.holdingUpstreamStep(t)
	recheck := func() { r.conf.InternalMp.transfers.zones[canonicalName(r.zone)].at = time.Now().Add(-transferRecheck) }

	// no answer: nothing is known of what they served
	serving(t, nil, nil)
	if upstreamHolds(r.conf, r.zone, step) {
		t.Error("held while the nameservers do not answer")
	}
	recheck()
	old, oldPriv := signingKey(t, r.zone)
	serving(t, soa(t, r.zone, 9, old, oldPriv), nil)
	if upstreamHolds(r.conf, r.zone, step) {
		t.Error("held while the nameservers serve the old upstream's copy")
	}
	recheck()
	serving(t, soa(t, r.zone, 8, r.key, r.priv), nil)
	if upstreamHolds(r.conf, r.zone, step) {
		t.Error("held at serial 8, below the 9 the nameservers served, though above the zone's copy at 1")
	}
	recheck()
	var asked []string
	serving(t, soa(t, r.zone, 9, r.key, r.priv), &asked)
	if !upstreamHolds(r.conf, r.zone, step) {
		t.Error("not held once the nameservers serve the new upstream's copy at the serial they served")
	}
	if !slices.Equal(asked, srNameservers) {
		t.Errorf("asked %v, want each of the provider's own nameservers", asked)
	}
	// a server role's step is not an upstream's
	if serverStep := serverRoleStep(srNewcomer); !upstreamHolds(r.conf, r.zone, serverStep) {
		t.Error("an upstream's check held up a server role's step")
	}

	other := newServingRig(t, "other.upstream.example.", "b.role.example.")
	serving(t, nil, nil)
	if !upstreamHolds(other.conf, other.zone, upstreamStep(srNewcomer)) {
		t.Error("another agent's part of the step waits for the provider's nameservers")
	}
}

// The join (external review of #365, N1): the provider's own agent leads, its
// parts and every other member hold the upstream's step, and the transition
// still does not move on, nor does its stamp tell the step held, while its
// nameservers serve the old upstream's copy. Once they serve the new
// upstream's, the turn takes the last step.
func TestAnUpstreamsStepHoldsTheTransitionUntilItsServersServe(t *testing.T) {
	const zone = "turn.upstream.example."
	u := newUpstreamMove(t, zone)
	r, st := u.reconcileRig, u.step
	key, priv := u.key, u.priv
	old, oldPriv := signingKey(t, zone)
	serving(t, soa(t, zone, 9, old, oldPriv), nil)

	everyMemberHolds := u.everyMemberHolds
	everyMemberHolds()
	r.turn(time.Now())
	if got, _ := r.step(); got.Number != st.Number {
		t.Fatalf("the transition moved on to %+v while the nameservers serve the old upstream's copy", got)
	}
	if r.own().StepHeld {
		t.Error("the stamp tells the step held while the nameservers serve the old upstream's copy")
	}

	r.conf.InternalMp.transfers.zones[canonicalName(zone)].at = time.Now().Add(-transferRecheck)
	serving(t, soa(t, zone, 9, key, priv), nil)
	if !r.own().StepHeld {
		t.Error("the stamp does not tell the step held once the nameservers serve the new upstream's copy")
	}
	r.turn(time.Now())
	got, ok := r.step()
	if !ok || got.Number != st.Number+1 || got.Taken[len(got.Taken)-1] != lastStepKey {
		t.Errorf("the last step was not taken: number %d of %d, taken %v", got.Number, got.Of, got.Taken)
	}
}

// upstreamMove is the rig of a transition that moves a's upstream from b to
// n, with a leading: thawed, n's key known here, and the upstream's step taken.
type upstreamMove struct {
	*reconcileRig
	key  *dns.DNSKEY // the new upstream's
	priv crypto.Signer
	step InstrStep
}

func newUpstreamMove(t *testing.T, zone string) *upstreamMove {
	t.Helper()
	r := newReconcileRig(t, zone, roleA)
	records := func(upstream string) []string {
		return []string{`3600 IN HSYNC3 ON a ` + roleA + ` ` + upstream, `3600 IN HSYNC3 ON b ` + roleB + ` .`, `3600 IN HSYNC3 ON n ` + roleN + ` .`}
	}
	const param = `servers="a,b,n" signers="b,n"`
	r.n, r.v = jAt(t, 41, param, records("b")...), jAt(t, 42, param, records("n")...)
	if rs := judgeTransition(r.n, r.v); len(rs) > 0 {
		t.Fatalf("the transition is refused: %v", rs)
	}
	knownAs(t, r.store, zone, r.n)
	r.agree()
	r.hear(roleN, r.agreeing(), true)
	r.thawNow()

	r.conf.MpConfig().Local.Nameservers = srNameservers
	r.conf.InternalMp.transfers.start = func(check func()) { check() }
	key, priv := signingKey(t, zone)
	nod := tdns.NewOwnerData(zone)
	nod.RRtypes.Set(dns.TypeDNSKEY, core.RRset{RRs: []dns.RR{key}})
	ar, _ := NewAgentRepo()
	ar.Set(roleN, nod)
	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	zdr.Repo.Set(ZoneName(zone), ar)
	r.conf.InternalMp.ZoneDataRepo = zdr

	u := &upstreamMove{reconcileRig: r, key: key, priv: priv}
	u.everyMemberHolds()
	r.turn(time.Now())
	st, ok := r.step()
	if !ok || !slices.Equal(st.Taken, []string{upstreamKey + roleA}) {
		t.Fatalf("the upstream's step was not taken: %+v", st)
	}
	u.step = st
	return u
}

func (u *upstreamMove) everyMemberHolds() {
	u.partsTake()
	u.holdsToo(roleB)
	u.holdsToo(roleN)
}

// check is the provider's next check of its nameservers, and whether the
// step is held after it.
func (u *upstreamMove) check() bool {
	if c := u.conf.InternalMp.transfers.zones[canonicalName(u.zone)]; c != nil {
		c.at = time.Now().Add(-transferRecheck)
	}
	return upstreamHolds(u.conf, u.zone, u.step)
}

// floorOnDisk is the floor a store read from disk now holds for the step.
func (u *upstreamMove) floorOnDisk() (uint32, bool) {
	u.t.Helper()
	return loadStore(u.t, u.hdb).floorFor(u.zone, u.conf.stepName(u.zone, u.step))
}

// The project owner's ruling on reading 1 (2026-11-05, CodeRabbit on #365):
// what the nameservers served at the step's first check outlives a restart.
// Asked again after one, a server that has moved meanwhile sets its own floor.
func TestARestartBetweenTheFirstCheckAndTheServingCheckRefusesALowerSerial(t *testing.T) {
	const zone = "floor.upstream.example."
	u := newUpstreamMove(t, zone)
	old, oldPriv := signingKey(t, zone)
	serving(t, soa(t, zone, 9, old, oldPriv), nil)
	if u.check() {
		t.Fatal("held while the nameservers serve the old upstream's copy")
	}
	if got, ok := u.floorOnDisk(); !ok || got != 9 {
		t.Fatalf("the floor on disk: %d %v, want 9", got, ok)
	}

	u.restart()
	serving(t, soa(t, zone, 8, u.key, u.priv), nil)
	if u.check() {
		t.Error("held at serial 8 after a restart, below the 9 the nameservers served")
	}
	serving(t, soa(t, zone, 9, u.key, u.priv), nil)
	if !u.check() {
		t.Error("not held at the serial they served, on the new upstream's signatures")
	}
}

// A restart with no floor kept yet: nothing is known of what they served, so
// the first answer sets it, and that one outlives the next restart too. A
// check with a nameserver that does not answer sets none.
func TestARestartBeforeAnyFirstCheckTakesTheFirstAnswerAsTheFloor(t *testing.T) {
	const zone = "first.upstream.example."
	u := newUpstreamMove(t, zone)
	if got, ok := u.floorOnDisk(); ok {
		t.Fatalf("a floor before any check: %d", got)
	}

	u.restart()
	serving(t, nil, nil)
	if u.check() {
		t.Fatal("held while the nameservers do not answer")
	}
	if got, ok := u.floorOnDisk(); ok {
		t.Fatalf("a floor from no answer: %d", got)
	}
	old, oldPriv := signingKey(t, zone)
	serving(t, soa(t, zone, 7, old, oldPriv), nil)
	if u.check() {
		t.Fatal("held while the nameservers serve the old upstream's copy")
	}
	if got, ok := u.floorOnDisk(); !ok || got != 7 {
		t.Fatalf("the floor on disk: %d %v, want the first answer, 7", got, ok)
	}

	u.restart()
	serving(t, soa(t, zone, 6, u.key, u.priv), nil)
	if u.check() {
		t.Error("held at serial 6, below the first answer's 7")
	}
	serving(t, soa(t, zone, 7, u.key, u.priv), nil)
	if !u.check() {
		t.Error("not held at the first answer's serial")
	}
}

// The floor goes when its step ends, on disk too, and no later step reads it:
// not the same step told again, which keeps it, but the transition's next
// step, its end, and a next transition at an agent that missed that end. A
// later transition that moves the same provider again has the same key and
// the same sets, and starts over: its first answer may be lower.
func TestANewStepDoesNotReadAnOldStepsFloor(t *testing.T) {
	floorAt9 := func(t *testing.T, zone string) *upstreamMove {
		t.Helper()
		u := newUpstreamMove(t, zone)
		old, oldPriv := signingKey(t, zone)
		serving(t, soa(t, zone, 9, old, oldPriv), nil)
		if u.check() {
			t.Fatal("held while the nameservers serve the old upstream's copy")
		}
		if got, ok := u.floorOnDisk(); !ok || got != 9 {
			t.Fatalf("the floor on disk: %d %v, want 9", got, ok)
		}
		return u
	}
	active := func(u *upstreamMove) SerialDigest { return sd(u.v) }

	t.Run("the same step told again keeps it", func(t *testing.T) {
		u := floorAt9(t, "again.floor.upstream.example.")
		if err := u.store.setStep(u.zone, active(u), u.step, nil); err != nil {
			t.Fatal(err)
		}
		if got, ok := u.floorOnDisk(); !ok || got != 9 {
			t.Errorf("the floor on disk: %d %v, want 9", got, ok)
		}
	})
	ends := map[string]func(t *testing.T, u *upstreamMove){
		"the next step": func(t *testing.T, u *upstreamMove) {
			next := u.step
			next.Number, next.Taken = next.Number+1, append(slices.Clone(next.Taken), lastStepKey)
			if err := u.store.setStep(u.zone, active(u), next, nil); err != nil {
				t.Fatal(err)
			}
		},
		"the transition's end": func(t *testing.T, u *upstreamMove) {
			if err := u.store.Done(u.zone); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, end := range ends {
		t.Run(name, func(t *testing.T) {
			u := floorAt9(t, "end.floor.upstream.example.")
			end(t, u)
			if got, ok := u.floorOnDisk(); ok {
				t.Errorf("the floor outlived the step: %d", got)
			}
			if st := loadStore(t, u.hdb).zones[u.zone]; st.StepFloor != nil {
				t.Errorf("the record on disk keeps %+v", st.StepFloor)
			}
		})
	}
	t.Run("a later move of the same provider", func(t *testing.T) {
		for name, ended := range map[string]bool{"after the end": true, "at an agent that missed the end": false} {
			t.Run(name, func(t *testing.T) {
				u := floorAt9(t, "later.floor.upstream.example.")
				if ended {
					if err := u.store.Done(u.zone); err != nil {
						t.Fatal(err)
					}
				}
				next := jAt(t, 43, `servers="a,b,n" signers="b,n"`, `3600 IN HSYNC3 ON a `+roleA+` n`, `3600 IN HSYNC3 ON b `+roleB+` .`, `3600 IN HSYNC3 ON n `+roleN+` .`)
				u.store.Note(u.zone, next, nil)
				if err := u.store.Activate(u.zone, Thaw{From: sd(u.v), To: sd(next)}); err != nil {
					t.Fatal(err)
				}
				if f := loadStore(t, u.hdb).zones[u.zone].StepFloor; f != nil {
					t.Fatalf("the next transition keeps the floor: %+v", f)
				}
				if err := u.store.setStep(u.zone, sd(next), u.step, nil); err != nil {
					t.Fatal(err)
				}
				serving(t, soa(t, u.zone, 5, u.key, u.priv), nil)
				if !u.check() {
					t.Error("not held at the new step's first answer: it read the old step's floor")
				}
				if got, ok := u.floorOnDisk(); !ok || got != 5 {
					t.Errorf("the floor on disk: %d %v, want 5", got, ok)
				}
			})
		}
	})
}

// A floor that cannot go on disk fails the check, though the nameservers serve
// as they should: a pass against it would not outlive a restart. A check for a
// step the store no longer holds keeps nothing and passes nothing, nor does it
// read the floor of the step it does hold.
func TestAFloorThatCannotBeKeptFailsTheCheck(t *testing.T) {
	t.Run("the disk fails", func(t *testing.T) {
		u := newUpstreamMove(t, "disk.floor.upstream.example.")
		serving(t, soa(t, u.zone, 9, u.key, u.priv), nil)
		u.hdb.DB.Close()
		if u.check() {
			t.Error("held on a floor that did not go on disk")
		}
	})
	stale := func(u *upstreamMove) InstrStep {
		st := u.step
		st.Digest = "moved-on"
		return st
	}
	t.Run("the step moved on, with no floor", func(t *testing.T) {
		u := newUpstreamMove(t, "stale.floor.upstream.example.")
		serving(t, soa(t, u.zone, 9, u.key, u.priv), nil)
		if upstreamHolds(u.conf, u.zone, stale(u)) {
			t.Error("held for a step the store does not hold")
		}
		if got, ok := u.floorOnDisk(); ok {
			t.Errorf("a stale check kept a floor: %d", got)
		}
	})
	t.Run("the step moved on, with the step's floor kept", func(t *testing.T) {
		u := newUpstreamMove(t, "stale2.floor.upstream.example.")
		old, oldPriv := signingKey(t, u.zone)
		serving(t, soa(t, u.zone, 9, old, oldPriv), nil)
		if u.check() {
			t.Fatal("held while the nameservers serve the old upstream's copy")
		}
		serving(t, soa(t, u.zone, 10, u.key, u.priv), nil)
		if upstreamHolds(u.conf, u.zone, stale(u)) {
			t.Error("held for a step the store does not hold, by the floor of the one it does")
		}
		if got, ok := u.floorOnDisk(); !ok || got != 9 {
			t.Errorf("the floor on disk: %d %v, want 9", got, ok)
		}
	})
}

// The status: every agent says whose nameservers the step waits for; the
// provider's own says at once what its operator must point where, since
// nothing moves until it does; nothing once held.
func TestTheStatusSaysWhatTheOperatorMustPointForAnUpstream(t *testing.T) {
	r := newServingRig(t, "status.upstream.example.", srNewcomer)
	step := r.holdingUpstreamStep(t)
	want := "waiting for n.role.example.'s nameservers to serve the zone from its new upstream"
	point := "; its operator must point ns1.n.example., ns2.n.example. at a.role.example. for the zone's transfer"
	now := time.Now()
	if got := upstreamStatus(r.conf, r.zone, heldStep{InstrStep: step, at: now}, now); got != want+point {
		t.Errorf("the provider's status: %q, want %q", got, want+point)
	}
	other := newServingRig(t, "status.other.upstream.example.", "b.role.example.")
	if got := upstreamStatus(other.conf, other.zone, heldStep{InstrStep: step, at: now}, now); got != want {
		t.Errorf("another agent's status: %q, want %q", got, want)
	}
	if got := upstreamStatus(r.conf, r.zone, heldStep{InstrStep: serverRoleStep(srNewcomer), at: now}, now); got != "" {
		t.Errorf("the status of a server role's step: %q", got)
	}
	serving(t, soa(t, r.zone, 1, r.key, r.priv), nil)
	if !upstreamHolds(r.conf, r.zone, step) {
		t.Fatal("not held")
	}
	if got := upstreamStatus(r.conf, r.zone, heldStep{InstrStep: step, at: now}, now); got != "" {
		t.Errorf("the status once held: %q", got)
	}
}

// signalRig is a leader's rig of a transition between two HSYNCPARAMs, and
// the KEYs that reach the queue to its combiner.
type signalRig struct {
	*reconcileRig
	sent chan *ZoneUpdate
}

// signalLeader is a signalRig from nParam to vParam, thawed, with the zone's
// KEY published and held when withKey says so.
func signalLeader(t *testing.T, zone, nParam, vParam string, withKey bool) *signalRig {
	t.Helper()
	r := &signalRig{reconcileRig: newReconcileRig(t, zone, roleA), sent: make(chan *ZoneUpdate, 4)}
	if withKey {
		mpzd, _ := Zones.Get(zone)
		mpzd.KeyDB = newMPTestKeyDB(t)
		publishKEY(t, mpzd, testSig0Key(t, mpzd.KeyDB, zone))
	}
	r.n, r.v = jAt(t, 41, nParam, freezeRecords...), jAt(t, 42, vParam, freezeRecords...)
	if rs := judgeTransition(r.n, r.v); len(rs) > 0 {
		t.Fatalf("the transition is refused: %v", rs)
	}
	knownAs(t, r.store, zone, r.n)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r.conf.InternalMp.MPTransport.TransportManager.StartReliableQueue(ctx, func(_ context.Context, m *transport.OutgoingMessage) error {
		if u, ok := m.Payload.(*ZoneUpdate); ok && m.RecipientID == string(freezeCombiner) {
			r.sent <- u
		}
		return nil
	})
	r.agree()
	r.thawNow()
	return r
}

// takeNextStep is the leader's next step: the step held is held everywhere,
// and it takes the one after it.
func (r *signalRig) takeNextStep() InstrStep {
	r.t.Helper()
	r.partsTake()
	r.holdsToo(roleB)
	r.turn(time.Now())
	st, ok := r.step()
	if !ok {
		r.t.Fatal("no step taken")
	}
	return st
}

// keySent is the publish instruction the KEY went to the combiner with.
func (r *signalRig) keySent() *core.PublishInstruction {
	r.t.Helper()
	u, ok := recvWithin(r.sent, 5*time.Second)
	if !ok || u.Publish == nil {
		r.t.Fatalf("no KEY with its instruction went to the combiner: %+v", u)
	}
	return u.Publish
}

// wantNoKeySent: nothing is on the queue to the combiner.
func (r *signalRig) wantNoKeySent(when string) {
	r.t.Helper()
	if slices.ContainsFunc(r.queue.GetPendingMessages(), func(m transport.PendingMessageInfo) bool { return m.RecipientID == string(freezeCombiner) }) {
		r.t.Errorf("%s: something is on the queue to the combiner", when)
	}
}

// dsbootCombiner is a combiner rig whose provider zone takes the _dsboot
// types, with the customer zone zone loaded, its copy's HSYNCPARAM params.
type dsbootCombiner struct {
	*consentCombiner
	conf *Config
	zone string
}

func newDsbootCombiner(t *testing.T, zone, params string, extra ...string) *dsbootCombiner {
	t.Helper()
	c := newConsentCombiner(t)
	RegisterProviderZoneRRtypes(ProviderZoneConf{Zone: consentProviderZone, AllowedRRtypes: []string{"KEY", "CDS", "CDNSKEY"}})
	withActing(t, c.hdb)
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(c.mp)
	c.start(consentProviderZone, zone)
	c.load(consentProviderZone, consentProviderText())
	d := &dsbootCombiner{consentCombiner: c, conf: conf, zone: zone}
	mpzd := c.load(zone, d.customerText(params, extra...))
	mpzd.Ready = true
	return d
}

func (d *dsbootCombiner) customerText(params string, extra ...string) string {
	z := d.zone
	text := fmt.Sprintf("%s 3600 IN SOA ns1.%s hostmaster.%s 1 7200 1800 604800 7200\n%s 3600 IN NS %s\n", z, z, z, z, consentNS1)
	for _, r := range append(slices.Clone(d.records(params)), extra...) {
		text += z + " " + r + "\n"
	}
	return text
}

func (d *dsbootCombiner) records(params string) []string {
	return []string{`3600 IN HSYNC3 ON alpha ` + consentAgent + ` .`, `3600 IN HSYNCPARAM ` + numberedText(params)}
}

// hand has the combiner's agent hand it the sets at step, of the instructions
// params: pubkey and pubcds as the step says, whatever the copy does.
func (d *dsbootCombiner) hand(params string, step int, pubkey, pubcds bool) {
	d.t.Helper()
	h := handoverFor(d.t, d.zone, d.records(params)...)
	h.Step, h.Sets.Pubkey, h.Sets.Pubcds = step, pubkey, pubcds
	if resp := handTo(d.conf, h, consentAgent); resp.Status != "ok" {
		d.t.Fatalf("the hand-over: %s: %s", resp.Status, resp.Message)
	}
}

// served is the records of rrtype at the zone's _dsboot name under ns, as the
// provider zone serves them.
func (d *dsbootCombiner) served(ns string, rrtype uint16) []string {
	d.t.Helper()
	prov, _ := Zones.Get(consentProviderZone)
	return servedNames(d.t, prov.ZoneData, dsbootOwnerName(d.zone, ns), rrtype)
}

func (d *dsbootCombiner) cds(text string) {
	d.t.Helper()
	d.update(d.zone, []core.RROperation{{Operation: "replace", RRtype: "CDS", Records: []string{d.zone + " " + text}}}, nil)
}

// pubkey on (design 5.6): the judge agrees it; one step gives the flag in the
// sets, its agent hands them, and the leader sends the zone's KEY with its
// instruction, at-ns now, to its combiner and the zone's other agents; a
// combiner that takes that instruction publishes the KEY at the _signal names
// (the join: the instruction the leader made is the one it takes). With no
// key published yet nothing goes: its take-up carries it.
func TestPubkeyOnPublishesTheKEYAtTheSignalNames(t *testing.T) {
	const n, v = `servers="a,b" nsmgmt="agent" suffix="n"`, `servers="a,b" nsmgmt="agent" pubkey suffix="v"`
	r := signalLeader(t, "pubkey.on.example.", n, v, true)
	r.wantNoKeySent("before the step")
	st := r.takeNextStep()
	if !slices.Equal(st.Taken, []string{pubkeyStepKey}) || st.Of != 2 || st.What != "the zone's KEY at the _signal names published" {
		t.Fatalf("the step: %+v", st)
	}
	if h := r.wanted(); h == nil || !h.Sets.Pubkey {
		t.Fatalf("the combiner is not handed pubkey at the step: %+v", h)
	}
	sent := r.keySent()
	if !slices.Contains(sent.Locations, "at-ns") {
		t.Fatalf("the KEY the step sends: %+v, want at-ns", sent)
	}

	const zone = "pubkey.signal.example."
	const params = `servers="alpha" nsmgmt="agent" parentsync="agent" pubkey`
	d := newDsbootCombiner(t, zone, params)
	logs := captureLog(t)
	d.hand(params, 1, true, false)
	key := consentKey(zone)
	d.update(zone, []core.RROperation{{Operation: "replace", RRtype: "KEY", Records: []string{key}}},
		&core.PublishInstruction{KEYRRs: []string{key}, Locations: sent.Locations})
	d.wantSignalKey("at the step", zone, consentNS1)
	if !strings.Contains(logs.String(), `msg="the zone's KEY at the _signal names published"`) {
		t.Errorf("no log line for the publication: %s", logs)
	}

	noKey := signalLeader(t, "pubkey.nokey.example.", n, v, false)
	if st := noKey.takeNextStep(); !slices.Equal(st.Taken, []string{pubkeyStepKey}) {
		t.Fatalf("the step with no key: %+v", st)
	}
	noKey.wantNoKeySent("with no key published")
}

// A KEY the queue does not take, for the combiner or for an agent, goes again:
// the step that gives pubkey is not left until it has gone, whatever else
// holds the step, and the status says what it waits for. It is tried every
// keySendRetry.
func TestThePubkeyStepWaitsUntilItsKEYIsQueued(t *testing.T) {
	const n, v = `servers="a,b" nsmgmt="agent" suffix="n"`, `servers="a,b" nsmgmt="agent" pubkey suffix="v"`
	for _, tc := range []struct {
		name   string
		filled bool // the queue takes nothing; else the combiner's and no more
	}{
		{"its combiner", true},
		{"an agent", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := signalLeader(t, "pubkey.unqueued.example.", n, v, true)
			tm := r.conf.InternalMp.MPTransport
			full := transport.NewReliableMessageQueue(&transport.ReliableMessageQueueConfig{MaxQueueSize: 1})
			if tc.filled {
				if err := full.Enqueue(&transport.OutgoingMessage{DistributionID: "x", RecipientID: roleB, Zone: r.zone, Payload: &ZoneUpdate{}}); err != nil {
					t.Fatal(err)
				}
			}
			tm.ReliableQueue = full
			st := r.takeNextStep()
			if !slices.Equal(st.Taken, []string{pubkeyStepKey}) {
				t.Fatalf("the step: %+v", st)
			}
			if got := full.GetPendingMessages(); len(got) != 1 {
				t.Fatalf("what the queue took: %+v", got)
			} else if !tc.filled && got[0].RecipientID != string(freezeCombiner) {
				t.Fatalf("what the queue took first: %+v", got[0])
			}

			wantWaiting := func(when string, at time.Time) {
				t.Helper()
				r.partsTake()
				r.holdsToo(roleB)
				r.turn(at)
				if got, _ := r.step(); got.Number != st.Number {
					t.Fatalf("%s: the step was left: %+v", when, got)
				}
				if line := r.conf.reconcileLine(r.zone, at); !strings.Contains(line, "the zone's KEY to go to the _signal names") {
					t.Errorf("%s: the status: %s", when, line)
				}
			}
			wantWaiting("the send failed", time.Now())
			wantWaiting("it failed again", time.Now().Add(keySendRetry))

			tm.ReliableQueue = r.queue
			wantWaiting("the queue takes it, before its time", time.Now())
			r.wantNoKeySent("before its time")

			r.partsTake()
			r.holdsToo(roleB)
			r.turn(time.Now().Add(keySendRetry))
			if sent := r.keySent(); !slices.Contains(sent.Locations, "at-ns") {
				t.Errorf("the KEY sent again: %+v, want at-ns", sent)
			}
			if got, _ := r.step(); got.Number != st.Number+1 || got.Taken[len(got.Taken)-1] != lastStepKey {
				t.Errorf("the step once the KEY has gone: %+v", got)
			}
		})
	}
}

// pubkey off: the step takes the flag out of the sets, and nothing is sent:
// handed the sets, the combiner withdraws the KEY from the _signal names at
// once, though its copy still says pubkey.
func TestPubkeyOffWithdrawsIt(t *testing.T) {
	r := signalLeader(t, "pubkey.off.example.", `servers="a,b" nsmgmt="agent" pubkey suffix="n"`, `servers="a,b" nsmgmt="agent" suffix="v"`, true)
	st := r.takeNextStep()
	if !slices.Equal(st.Taken, []string{pubkeyStepKey}) || st.What != "the zone's KEY at the _signal names withdrawn" {
		t.Fatalf("the step: %+v", st)
	}
	if h := r.wanted(); h == nil || h.Sets.Pubkey {
		t.Fatalf("the combiner is still handed pubkey: %+v", h)
	}
	r.wantNoKeySent("at a withdrawal")

	const zone = "pubkey.withdrawn.example."
	const params = `servers="alpha" nsmgmt="agent" parentsync="agent" pubkey`
	d := newDsbootCombiner(t, zone, params)
	d.hand(params, 0, true, false)
	d.sendKey(zone)
	d.wantSignalKey("before the step", zone, consentNS1)
	logs := captureLog(t)
	d.hand(params, 1, false, false)
	d.wantNoSignalKey("at the step", zone, consentNS1)
	if !strings.Contains(logs.String(), `msg="the zone's KEY at the _signal names withdrawn"`) {
		t.Errorf("no log line for the withdrawal: %s", logs)
	}
}

// pubcds on: one step gives the flag in the sets, and no message but the
// hand-over: the combiner publishes the apex's CDS and CDNSKEY at the _dsboot
// names under its nameservers. They follow the apex at a key roll and the
// nameservers at an NS change.
func TestPubcdsOnPublishesTheCDSAtTheSignalNames(t *testing.T) {
	r := signalLeader(t, "pubcds.on.example.", `servers="a,b" nsmgmt="agent" suffix="n"`, `servers="a,b" nsmgmt="agent" pubcds suffix="v"`, true)
	st := r.takeNextStep()
	if !slices.Equal(st.Taken, []string{pubcdsStepKey}) || st.Of != 2 || st.What != "the zone's CDS at the _signal names published" {
		t.Fatalf("the step: %+v", st)
	}
	if h := r.wanted(); h == nil || !h.Sets.Pubcds || h.Sets.Pubkey {
		t.Fatalf("the sets at the step: %+v", h)
	}
	r.wantNoKeySent("for pubcds")

	const zone = "pubcds.signal.example."
	const params = `servers="alpha" signers="alpha" nsmgmt="agent" parentsync="agent" pubcds`
	d := newDsbootCombiner(t, zone, params, okCDNSKEY)
	d.hand(params, 0, false, false)
	d.cds(okCDS)
	if got := d.served(consentNS1, dns.TypeCDS); got != nil {
		t.Fatalf("a _dsboot CDS before the step: %v", got)
	}
	logs := captureLog(t)
	d.hand(params, 1, false, true)
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 || !strings.Contains(got[0], "12345") {
		t.Errorf("the CDS at the step: %v", got)
	}
	if got := d.served(consentNS1, dns.TypeCDNSKEY); len(got) != 1 {
		t.Errorf("the CDNSKEY at the step: %v", got)
	}
	if !strings.Contains(logs.String(), `msg="the zone's CDS at the _signal names published"`) {
		t.Errorf("no log line for the publication: %s", logs)
	}

	d.cds(okCDSRolled)
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 || !strings.Contains(got[0], "54321") {
		t.Errorf("the CDS after a key roll: %v", got)
	}
	d.addNS(zone, consentNS2)
	if got := d.served(consentNS2, dns.TypeCDS); len(got) != 1 || !strings.Contains(got[0], "54321") {
		t.Errorf("the CDS under a nameserver added: %v", got)
	}
}

// pubcds off: handed the sets, the combiner withdraws the names and publishes
// the provider zone without them, in the memory, the file and the store a
// restart loads.
func TestPubcdsOffWithdrawsIt(t *testing.T) {
	r := signalLeader(t, "pubcds.off.example.", `servers="a,b" nsmgmt="agent" pubcds suffix="n"`, `servers="a,b" nsmgmt="agent" suffix="v"`, true)
	if st := r.takeNextStep(); !slices.Equal(st.Taken, []string{pubcdsStepKey}) || st.What != "the zone's CDS at the _signal names withdrawn" {
		t.Fatalf("the step: %+v", st)
	}
	if h := r.wanted(); h == nil || h.Sets.Pubcds {
		t.Fatalf("the sets at the step: %+v", h)
	}

	const zone = "pubcds.withdrawn.example."
	const params = `servers="alpha" signers="alpha" nsmgmt="agent" parentsync="agent" pubcds`
	d := newDsbootCombiner(t, zone, params, okCDNSKEY)
	d.hand(params, 0, false, true)
	d.cds(okCDS)
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 {
		t.Fatalf("the CDS before the step: %v", got)
	}
	logs := captureLog(t)
	d.hand(params, 1, false, false)
	for _, rrtype := range dsbootTypes {
		if got := d.served(consentNS1, rrtype); got != nil {
			t.Errorf("a _dsboot %s after the step: %v", dns.TypeToString[rrtype], got)
		}
	}
	if !strings.Contains(logs.String(), `msg="the zone's CDS at the _signal names withdrawn"`) {
		t.Errorf("no log line for the withdrawal: %s", logs)
	}
	all, err := LoadAllContributions(d.hdb)
	if err != nil {
		t.Fatal(err)
	}
	for owner := range all[consentProviderZone][consentAgent] {
		if strings.HasPrefix(owner, "_dsboot.") {
			t.Errorf("a _dsboot name in the store a restart loads: %s", owner)
		}
	}
}

// The publication follows the step: at the agent the sets at the step, not V
// and not the copy, say whether the KEY goes at-ns, and what its combiner is
// handed; at the combiner a copy that says pubcds publishes nothing until the
// sets do, and a copy that still says it withdraws nothing once they do not.
// A combiner handed nothing leaves what it serves.
func TestTheSignalPublicationFollowsTheStepNotTheCopy(t *testing.T) {
	const zone = "follows.step.example."
	r := signalLeader(t, zone, `servers="a,b" nsmgmt="agent" suffix="n"`, `servers="a,b" nsmgmt="agent" pubkey pubcds suffix="v"`, true)
	if locs := publishLocations(ZoneName(zone)); slices.Contains(locs, "at-ns") {
		t.Errorf("at-ns under the sets of step 0, though V says pubkey: %v", locs)
	}
	if h := r.wanted(); h != nil && (h.Sets.Pubkey || h.Sets.Pubcds) {
		t.Errorf("handed V's flags at step 0: %+v", h.Sets)
	}
	st := r.takeNextStep()
	if !slices.Equal(st.Taken, []string{pubkeyStepKey}) {
		t.Fatalf("the first step: %+v", st)
	}
	if locs := publishLocations(ZoneName(zone)); !slices.Contains(locs, "at-ns") {
		t.Errorf("no at-ns at the step that gives pubkey: %v", locs)
	}
	if h := r.wanted(); h == nil || !h.Sets.Pubkey || h.Sets.Pubcds {
		t.Errorf("the sets at the first step: %+v", h)
	}
	st = r.takeNextStep()
	if !slices.Equal(st.Taken, []string{pubkeyStepKey, pubcdsStepKey}) || st.Of != 3 {
		t.Fatalf("the second step: %+v", st)
	}
	if h := r.wanted(); h == nil || !h.Sets.Pubcds {
		t.Errorf("the sets at the second step: %+v", h)
	}

	const customer = "follows.copy.example."
	const params = `servers="alpha" signers="alpha" nsmgmt="agent" parentsync="agent" pubcds`
	d := newDsbootCombiner(t, customer, params, okCDNSKEY)
	mpzd, _ := Zones.Get(customer)
	if err := mpzd.syncDsbootNames(); err != nil {
		t.Fatal(err)
	}
	if got := d.served(consentNS1, dns.TypeCDNSKEY); got != nil {
		t.Errorf("a combiner handed nothing publishes by its copy: %v", got)
	}
	d.hand(params, 0, false, false)
	d.cds(okCDS)
	if got := d.served(consentNS1, dns.TypeCDS); got != nil {
		t.Errorf("published by the copy, with the sets saying no: %v", got)
	}
	d.hand(params, 1, false, true)
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 {
		t.Errorf("not published when the sets say so: %v", got)
	}
	d.hand(params, 2, false, false)
	if got := d.served(consentNS1, dns.TypeCDS); got != nil {
		t.Errorf("kept by the copy, with the sets saying no: %v", got)
	}
}

// A restart: the provider zone's file has no _dsboot name, and its first load
// serves what it held, whichever of the two zones loads first.
func TestTheDsbootNamesAreServedAgainAfterARestart(t *testing.T) {
	const zone = "restart.dsboot.example."
	const params = `servers="alpha" signers="alpha" nsmgmt="agent" parentsync="agent" pubcds`
	d := newDsbootCombiner(t, zone, params, okCDNSKEY)
	d.hand(params, 1, false, true)
	d.cds(okCDS)
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 {
		t.Fatalf("the CDS before the restart: %v", got)
	}
	d.start(consentProviderZone, zone)
	d.load(consentProviderZone, consentProviderText())
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 {
		t.Errorf("the provider zone's first load, the customer's yet to come: %v", got)
	}
	d.load(zone, d.customerText(params, okCDNSKEY))
	if got := d.served(consentNS1, dns.TypeCDNSKEY); len(got) != 1 {
		t.Errorf("after the customer's first load: %v", got)
	}

	d.start(consentProviderZone, zone)
	d.load(zone, d.customerText(params, okCDNSKEY))
	d.load(consentProviderZone, consentProviderText())
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 {
		t.Errorf("with the provider zone loaded last: %v", got)
	}
}

// A provider zone that does not allow a type does not get it, and says so.
func TestADsbootNameNeedsTheProviderZonesAllowedRRtypes(t *testing.T) {
	const zone = "allowed.dsboot.example."
	const params = `servers="alpha" signers="alpha" nsmgmt="agent" parentsync="agent" pubcds`
	d := newDsbootCombiner(t, zone, params, okCDNSKEY)
	RegisterProviderZoneRRtypes(ProviderZoneConf{Zone: consentProviderZone, AllowedRRtypes: []string{"KEY", "CDS"}})
	d.hand(params, 0, false, true)
	d.cds(okCDS)
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 {
		t.Errorf("the type allowed: %v", got)
	}
	if got := d.served(consentNS1, dns.TypeCDNSKEY); got != nil {
		t.Errorf("the type not allowed: %v", got)
	}
}

// A type its allowed-rrtypes no longer allow, once published, goes: the
// combine alone would leave it served, and its contribution held and saved.
// The other type stays. allowed-rrtypes are read at a start; a file written
// by an earlier run can bring such a name back, and only this takes it out.
func TestADsbootTypeNoLongerAllowedIsWithdrawn(t *testing.T) {
	const zone = "disallowed.dsboot.example."
	const params = `servers="alpha" signers="alpha" nsmgmt="agent" parentsync="agent" pubcds`
	d := newDsbootCombiner(t, zone, params, okCDNSKEY)
	d.hand(params, 0, false, true)
	d.cds(okCDS)
	if got := d.served(consentNS1, dns.TypeCDNSKEY); len(got) != 1 {
		t.Fatalf("the CDNSKEY while allowed: %v", got)
	}
	RegisterProviderZoneRRtypes(ProviderZoneConf{Zone: consentProviderZone, AllowedRRtypes: []string{"KEY", "CDS"}})
	mpzd, _ := Zones.Get(zone)
	if err := mpzd.syncDsbootNames(); err != nil {
		t.Fatal(err)
	}
	if got := d.served(consentNS1, dns.TypeCDNSKEY); got != nil {
		t.Errorf("the CDNSKEY no longer allowed is still served: %v", got)
	}
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 {
		t.Errorf("the CDS, still allowed: %v", got)
	}
	all, err := LoadAllContributions(d.hdb)
	if err != nil {
		t.Fatal(err)
	}
	if got := all[consentProviderZone][consentAgent][dsbootOwnerName(zone, consentNS1)][dns.TypeCDNSKEY].RRs; len(got) != 0 {
		t.Errorf("the CDNSKEY no longer allowed is in the store a restart loads: %v", got)
	}
}

// An update its _dsboot names could not follow (external review of #365, S1)
// stands: it is held and served, so it is confirmed. The names lag, and with
// no further update or hand-over the combiner's message loop brings them to
// the apex.
func TestADsbootSyncThatFailedOnAnUpdateIsTriedAgain(t *testing.T) {
	const zone = "retry.dsboot.example."
	const params = `servers="alpha" signers="alpha" nsmgmt="agent" parentsync="agent" pubcds`
	d := newDsbootCombiner(t, zone, params)
	d.hand(params, 1, false, true)
	d.cds(okCDS)
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 || !strings.Contains(got[0], "12345") {
		t.Fatalf("the CDS before the update: %v", got)
	}

	prov, _ := Zones.Get(consentProviderZone)
	prov.ZoneStore = tdns.XfrZone // its publish fails
	d.cds(okCDSRolled)            // fails the test unless confirmed ok
	store := actingHeld.Load()
	if got := store.zonesOwingDsboot(); !slices.Equal(got, []string{zone}) {
		t.Fatalf("the zones owing their names: %v", got)
	}

	prov.ZoneStore = tdns.MapZone
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 || !strings.Contains(got[0], "12345") {
		t.Errorf("the CDS the publish that failed left: %v", got)
	}
	saved := dsbootRetryInterval
	dsbootRetryInterval = 20 * time.Millisecond
	t.Cleanup(func() { dsbootRetryInterval = saved })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); CombinerMsgHandler(ctx, d.conf, &MsgQs{}, nil, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	waitUntil(t, "the combiner did not try the names again", func() bool { return len(store.zonesOwingDsboot()) == 0 })
	if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 || !strings.Contains(got[0], "54321") {
		t.Errorf("the CDS after the combiner tried again: %v", got)
	}
}

// A withdrawal whose publish failed: by the time it goes again the
// contributions are gone and the publish is all that is owed, as for a
// _signal KEY (retractSignalKey). The names are not settled while the provider
// zone serves them, whichever way it goes again: the combiner's loop or the
// agent handing the sets again, and that one is not told ok before they go.
func TestADsbootWithdrawalWhosePublishFailedIsPublishedWhenTriedAgain(t *testing.T) {
	const zone = "withdrawal.dsboot.example."
	const params = `servers="alpha" signers="alpha" nsmgmt="agent" parentsync="agent" pubcds`
	for _, tc := range []struct {
		name  string
		again func(d *dsbootCombiner, withdraw func() *CombinerSyncResponse)
	}{
		{"the combiner's loop", func(d *dsbootCombiner, _ func() *CombinerSyncResponse) { syncOwedDsbootNames() }},
		{"the agent", func(d *dsbootCombiner, withdraw func() *CombinerSyncResponse) {
			if resp := withdraw(); resp.Status != "ok" {
				d.t.Errorf("the hand-over again: %s: %s", resp.Status, resp.Message)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDsbootCombiner(t, zone, params)
			d.hand(params, 1, false, true)
			d.cds(okCDS)
			if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 {
				t.Fatalf("the CDS before the withdrawal: %v", got)
			}
			withdraw := func() *CombinerSyncResponse {
				h := handoverFor(t, zone, d.records(params)...)
				h.Step, h.Sets.Pubcds = 2, false
				return handTo(d.conf, h, consentAgent)
			}
			store := actingHeld.Load()
			prov, _ := Zones.Get(consentProviderZone)

			prov.ZoneStore = tdns.XfrZone // its publish fails
			if resp := withdraw(); resp.Status != "partial" {
				t.Fatalf("the withdrawal whose publish fails: %s: %s", resp.Status, resp.Message)
			}
			syncOwedDsbootNames() // and fails again
			if got := store.zonesOwingDsboot(); !slices.Equal(got, []string{zone}) {
				t.Fatalf("the zones owing their names while the publish fails: %v", got)
			}
			prov.ZoneStore = tdns.MapZone
			if got := d.served(consentNS1, dns.TypeCDS); len(got) != 1 {
				t.Fatalf("the CDS the publish that failed left: %v", got)
			}

			tc.again(d, withdraw)
			if got := d.served(consentNS1, dns.TypeCDS); len(got) != 0 {
				t.Errorf("the CDS once tried again: %v", got)
			}
			if got := store.zonesOwingDsboot(); len(got) != 0 {
				t.Errorf("the zones owing their names once tried again: %v", got)
			}
		})
	}
}

// S17a's roll and a step meet in sendZoneKEY. A roll's new KEY goes where the
// sets at the zone's step say, under the distribution it booked: at-apex
// alone before the step that gives pubkey, at-ns after it, and at-apex alone
// after the step that takes it. The step that gives pubkey during a roll
// sends the new key, whatever the leader's copy still serves, with at-ns, and
// leaves the roll's booking as it was.
func TestARollsNewKEYAndAStepsLocationsBothHold(t *testing.T) {
	const zone = "roll.signal.example."
	r := signalLeader(t, zone, `servers="a,b" nsmgmt="agent" suffix="n"`, `servers="a,b" nsmgmt="agent" pubkey suffix="v"`, true)
	z := ZoneName(zone)
	mpzd, _ := Zones.Get(zone)
	kdb := mpzd.KeyDB
	if _, err := kdb.Sig0KeyMgmt(nil, tdns.KeystorePost{Command: "sig0-mgmt", SubCommand: "generate", Zone: zone,
		Keyname: zone, Algorithm: dns.ED25519, State: tdns.Sig0StatePublished, Creator: "test"}); err != nil {
		t.Fatal(err)
	}
	rows, err := sig0Rows(kdb, z, tdns.Sig0StatePublished)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the new key: %v, %v", rows, err)
	}
	newKey := rows[0]
	active, err := activeSig0Rows(kdb, z)
	if err != nil || len(active) != 1 {
		t.Fatalf("the old key: %v, %v", active, err)
	}
	tm := r.conf.InternalMp.MPTransport

	if err := r.conf.publishRolledKEY(z, &newKey); err != nil {
		t.Fatal(err)
	}
	sent := r.keySent()
	if slices.Contains(sent.Locations, "at-ns") || !slices.Equal(sent.KEYRRs, []string{newKey.key.String()}) {
		t.Errorf("the roll's KEY under the sets of step 0: %+v", sent)
	}
	booked, ok := tm.rollKEYs.state(z)
	if !ok {
		t.Fatal("the roll's KEY is not booked")
	}
	if err := saveRoll(kdb, &sig0Roll{zone: z, phase: rollPublished, oldKeyid: active[0].keyid, newKeyid: newKey.keyid, started: time.Now()}); err != nil {
		t.Fatal(err)
	}

	st := r.takeNextStep()
	if !slices.Equal(st.Taken, []string{pubkeyStepKey}) {
		t.Fatalf("the step: %+v", st)
	}
	sent = r.keySent()
	if !slices.Contains(sent.Locations, "at-ns") || !slices.Equal(sent.KEYRRs, []string{newKey.key.String()}) {
		t.Errorf("the step's KEY during the roll: %+v, want the new key with at-ns", sent)
	}
	if again, ok := tm.rollKEYs.state(z); !ok || again.distID != booked.distID {
		t.Errorf("the step's send moved the roll's booking: %+v, was %+v", again, booked)
	}

	if err := r.conf.publishRolledKEY(z, &newKey); err != nil {
		t.Fatal(err)
	}
	if sent = r.keySent(); !slices.Contains(sent.Locations, "at-ns") {
		t.Errorf("the roll's KEY after the step: %+v, want at-ns", sent)
	}

	off := signalLeader(t, "roll.signal.off.example.", `servers="a,b" nsmgmt="agent" pubkey suffix="n"`, `servers="a,b" nsmgmt="agent" suffix="v"`, true)
	if st := off.takeNextStep(); !slices.Equal(st.Taken, []string{pubkeyStepKey}) {
		t.Fatalf("the step that takes pubkey: %+v", st)
	}
	offZone := ZoneName("roll.signal.off.example.")
	offMpzd, _ := Zones.Get(string(offZone))
	offRows, err := activeSig0Rows(offMpzd.KeyDB, offZone)
	if err != nil || len(offRows) != 1 {
		t.Fatalf("the key: %v, %v", offRows, err)
	}
	if err := off.conf.publishRolledKEY(offZone, &offRows[0]); err != nil {
		t.Fatal(err)
	}
	if sent := off.keySent(); slices.Contains(sent.Locations, "at-ns") {
		t.Errorf("a roll's KEY after the step that takes pubkey: %+v", sent)
	}
}
