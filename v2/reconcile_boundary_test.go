/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The reconciliation's step at the transport boundary (plan S12), over DNS.
 */
package tdnsmp

import (
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// Bob, a stand-in for the zone's leader, announces step 1 in his beat to
// alice. Alice takes it and hands it to her combiner and her signer. Her
// beat to bob tells the step held only after her combiner's confirmation
// and her signer's inventory: not with the combiner's alone.
func TestTransportBoundary_AStepIsHandedAndConfirmed(t *testing.T) {
	env := newIntegEnv(t, &integEnvConfig{AuthorizeAllPeers: true, ChunkMode: "edns0", ControlZoneIsIdentity: true})
	alice, bob := dns.Fqdn(env.Alice.Identity), dns.Fqdn(env.Bob.Identity)
	zone := "step.reconcile.example."
	zd := seedZoneWithHSYNC3(t, zone, alice, bob)
	addHSYNCPARAMServers(t, zd, shortLabel(alice), shortLabel(bob))
	zd.Options[tdns.OptMultiProvider] = true
	zd.Logger = log.New(io.Discard, "", 0)
	apex, err := zd.GetOwner(zone)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ReadInstructions(apex)
	if err != nil || n == nil {
		t.Fatalf("the zone's reading: %v %v", n, err)
	}
	v := *n
	v.Serial, v.Suffix = n.Serial+1, "stepped"
	thaw := Thaw{From: sd(n), To: sd(&v)}
	thawed := func(s *InstructionStore) {
		s.Note(zone, n, nil)
		enforced(t, s, zone)
		s.Note(zone, &v, nil)
		if err := s.Activate(zone, thaw); err != nil {
			t.Fatalf("Activate: %v", err)
		}
	}

	// bob, at step 1 of the transition: V's lists
	sb := newStore(t)
	thawed(sb)
	raw, digest, err := stepDigest(rolesFor(&v, &v, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.setStep(zone, sd(&v), InstrStep{Number: 1, Of: 1, What: "the last", Sets: raw, Digest: digest, Taken: []string{lastStepKey}}, nil); err != nil {
		t.Fatal(err)
	}
	bobStamps := newStampTable(bob, sb, 1, false, nil)
	env.Bob.Bridge.stamps = bobStamps

	// alice, at step 0, bob her leader, with a combiner and a signer that
	// hold what she hands them when the test says so
	sa := newStore(t)
	thawed(sa)
	prev := instrStore.Load()
	instrStore.Store(sa)
	t.Cleanup(func() { instrStore.Store(prev) })
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: alice})
	conf.InternalMp.Instructions = sa
	conf.InternalMp.MPTransport = env.Alice.Bridge
	conf.InternalMp.AgentRegistry = env.Alice.Registry
	lem := NewLeaderElectionManager(AgentId(alice), time.Hour, func(ZoneName, string, map[string][]string) error { return nil })
	t.Cleanup(func() { stopElectionTimers(lem) })
	lem.elections[ZoneName(zone)] = &LeaderElection{Zone: ZoneName(zone), Leader: AgentId(bob), LeaderExpiry: time.Now().Add(time.Hour)}
	conf.InternalMp.LeaderElectionManager = lem
	var mu sync.Mutex
	var handed []string // the hand-overs to the combiner, by distribution
	combiner := newHandoverTracker(AgentId(alice), func(_ ZoneName, u *ZoneUpdate, distID string) (string, error) {
		if u.Acting != nil {
			mu.Lock()
			handed = append(handed, distID)
			mu.Unlock()
		}
		return distID, nil
	})
	signer := newHandoverTracker(AgentId(alice), func(ZoneName, *ZoneUpdate, string) (string, error) { return "", nil })
	signer.toSigner = true
	conf.InternalMp.Handover, conf.InternalMp.SignerHandover = combiner, signer
	aliceStamps := newStampTable(alice, sa, 1, false, nil)
	aliceStamps.stepHeld = conf.holdsStep
	env.Alice.Bridge.stamps = aliceStamps

	// each listens over DNS, and knows the other
	listen := func(p *peerEnv) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serveDNS(t, env.ctx, ln, p)
		p.Bridge.StartIncomingMessageRouter(env.ctx)
		return ln.Addr().String()
	}
	addrA, addrB := listen(env.Alice), listen(env.Bob)
	for _, c := range []struct {
		p         *peerEnv
		other, at string
	}{{env.Alice, bob, addrB}, {env.Bob, alice, addrA}} {
		c.p.Registry.S.Set(AgentId(c.other), NewAgent(AgentId(c.other)))
		peer := peerFromAddress(c.other, c.at)
		peer.SetMechanismState("DNS", transport.PeerStateIntroducing, "said hello")
		if err := c.p.Bridge.PeerRegistry.Add(peer); err != nil {
			t.Fatal(err)
		}
	}
	beat := func(from, to *peerEnv) {
		t.Helper()
		agent := NewAgent(AgentId(to.Identity))
		agent.DnsMethod = true
		if resp, err := from.Bridge.SendBeatWithFallback(env.ctx, agent, 1); err != nil || resp == nil {
			t.Fatalf("the beat: %+v %v", resp, err)
		}
		if _, ok := recvWithin(to.MsgQs.Beat, integTestTimeout); !ok {
			t.Fatal("the beat did not arrive")
		}
	}
	heldAtBob := func() InstrStamp {
		t.Helper()
		m := bobStamps.heard(alice)
		if m == nil {
			t.Fatal("bob heard nothing of alice")
		}
		return m.Instr[canonicalName(zone)]
	}

	beat(env.Bob, env.Alice)
	conf.reconcileTurn(zone, time.Now())
	if in, _ := sa.reconcileInputs(zone); !in.hasStep || in.step.Number != 1 || in.step.Digest != digest {
		t.Fatalf("alice did not take bob's step: %+v", in.step)
	}
	mu.Lock()
	n1 := len(handed)
	mu.Unlock()
	if n1 == 0 {
		t.Fatal("alice handed her combiner nothing")
	}
	beat(env.Alice, env.Bob)
	if st := heldAtBob(); st.Step == nil || st.Step.Number != 1 || st.StepHeld {
		t.Fatalf("alice's stamp before her parts hold the step: %+v", st)
	}

	// the combiner's confirmation of the latest hand-over
	mu.Lock()
	last := handed[len(handed)-1]
	mu.Unlock()
	combiner.confirmation(last, transport.ConfirmSuccess)
	beat(env.Alice, env.Bob)
	if st := heldAtBob(); st.StepHeld {
		t.Fatal("alice's stamp tells the step held with her signer not holding it")
	}

	// the signer's inventory says it holds what alice wants
	signer.mu.Lock()
	want := signer.zones[handoverKey(zone)].want
	signer.mu.Unlock()
	signer.learned(zone, want)
	beat(env.Alice, env.Bob)
	st := heldAtBob()
	if !st.StepHeld || st.Step == nil || st.Step.Digest != digest || !st.Reconciling {
		t.Errorf("alice's stamp once both her parts hold the step: %+v", st)
	}
	if !strings.Contains(conf.reconcileLine(zone, time.Now()), "step 1 of 1 (the last)") {
		t.Errorf("alice's status: %q", conf.reconcileLine(zone, time.Now()))
	}
}
