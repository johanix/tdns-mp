/*
 * RFI CONFIG/AUDIT answers go first on the request's mechanism (#238), by the
 * transport's SendOn: a /msg that does not take the verb sends them over DNS,
 * a refusal the asker judged stays where it was made. A confirmation that
 * fails to deliver on its first choice counts against that mechanism (#236).
 */

package tdnsmp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
)

func TestTransportErrorAnswered(t *testing.T) {
	answered := transport.NewAnsweredTransportError("API", "config", "peer.", errors.New("not authorized"))
	if !transportErrorAnswered(answered) {
		t.Fatal("Answered refusal not recognised")
	}
	if transportErrorAnswered(transport.NewTransportError("API", "config", "peer.", errors.New("dial"), true)) {
		t.Fatal("dial error must not look Answered")
	}
	if transportErrorAnswered(errors.New("plain")) {
		t.Fatal("plain error must not look Answered")
	}
}

// A CONFIG answer on the request's HTTPS mechanism does not touch DNS (#238).
func TestConfigAnswerPrefersArrivalMechanism(t *testing.T) {
	me := newMechanismEnv(t, "config-answer.example.", httpsServes)
	b := me.Bob.Bridge
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	beforePosts, beforeNotifies := me.posts.Load(), me.notifies.Load()
	resp, err := b.sendConfig(ctx, me.aliceAtBob, transport.MechanismAPI, &PeerConfigRequest{
		SenderID: me.bob, Zone: me.zone, Subtype: "upstream",
		ConfigData: map[string]string{"xfr_srcs": "127.0.0.1"}, Timestamp: time.Now(),
	})
	if err != nil || !resp.Accepted || resp.Mechanism != transport.MechanismAPI {
		t.Fatalf("config over API: resp %+v err %v, want it taken over HTTPS", resp, err)
	}
	if me.posts.Load()-beforePosts != 1 {
		t.Errorf("POSTs delta %d, want 1 (answer on the request's HTTPS)", me.posts.Load()-beforePosts)
	}
	if me.notifies.Load()-beforeNotifies != 0 {
		t.Errorf("NOTIFYs delta %d, want 0 when HTTPS takes the answer", me.notifies.Load()-beforeNotifies)
	}

	beforePosts, beforeNotifies = me.posts.Load(), me.notifies.Load()
	aresp, err := b.sendAudit(ctx, me.aliceAtBob, transport.MechanismAPI, &PeerAuditRequest{
		SenderID: me.bob, Zone: me.zone, AuditData: map[string]string{"ok": "1"}, Timestamp: time.Now(),
	})
	if err != nil || !aresp.Accepted || aresp.Mechanism != transport.MechanismAPI {
		t.Fatalf("audit over API: resp %+v err %v, want it taken over HTTPS", aresp, err)
	}
	if me.posts.Load()-beforePosts != 1 || me.notifies.Load()-beforeNotifies != 0 {
		t.Errorf("audit: POSTs delta %d NOTIFYs delta %d, want 1 and 0",
			me.posts.Load()-beforePosts, me.notifies.Load()-beforeNotifies)
	}
}

// A config asked for over DNS is answered over DNS, though alice offers
// HTTPS.
func TestConfigAnswerOverDNSStaysOnDNS(t *testing.T) {
	me := newMechanismEnv(t, "config-answer-dns.example.", httpsServes)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := me.Bob.Bridge.sendConfig(ctx, me.aliceAtBob, transport.MechanismDNS, &PeerConfigRequest{
		SenderID: me.bob, Zone: me.zone, Subtype: "upstream",
		ConfigData: map[string]string{"xfr_srcs": "127.0.0.1"}, Timestamp: time.Now(),
	})
	if err != nil || !resp.Accepted || resp.Mechanism != transport.MechanismDNS {
		t.Fatalf("config over DNS: resp %+v err %v, want it taken over DNS", resp, err)
	}
	if p, n := me.posts.Load(), me.notifies.Load(); p != 0 || n != 1 {
		t.Errorf("%d POSTs and %d NOTIFYs, want the NOTIFY alone", p, n)
	}
}

// A /msg that does not take config and audit answers that they are not
// accepted there: nothing judged the answer, and it goes over DNS, the
// sig0key hand-over included. HTTPS delivered it, so nothing is counted
// against it (#270's review, S1).
func TestAnswerNotAcceptedOnMsgGoesOverDNS(t *testing.T) {
	me := newMechanismEnv(t, "answer-not-accepted.example.", httpsOlder)
	b := me.Bob.Bridge
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := b.sendConfig(ctx, me.aliceAtBob, transport.MechanismAPI, &PeerConfigRequest{
		SenderID: me.bob, Zone: me.zone, Subtype: "sig0key",
		ConfigData: map[string]string{"sig0key": "k"}, Timestamp: time.Now(),
	})
	if err != nil || !resp.Accepted || resp.Mechanism != transport.MechanismDNS {
		t.Fatalf("config not accepted on /msg: resp %+v err %v, want it taken over DNS", resp, err)
	}
	if p, n := me.posts.Load(), me.notifies.Load(); p != 1 || n != 1 {
		t.Errorf("config: %d POSTs and %d NOTIFYs, want 1 and 1", p, n)
	}

	aresp, err := b.sendAudit(ctx, me.aliceAtBob, transport.MechanismAPI, &PeerAuditRequest{
		SenderID: me.bob, Zone: me.zone, AuditData: map[string]string{"ok": "1"}, Timestamp: time.Now(),
	})
	if err != nil || !aresp.Accepted || aresp.Mechanism != transport.MechanismDNS {
		t.Fatalf("audit not accepted on /msg: resp %+v err %v, want it taken over DNS", aresp, err)
	}
	if p, n := me.posts.Load(), me.notifies.Load(); p != 2 || n != 2 {
		t.Errorf("audit: %d POSTs and %d NOTIFYs, want 2 and 2", p, n)
	}
	if n := me.aliceAtBob.MechanismConsecutiveFails(transport.MechanismAPI); n != 0 {
		t.Errorf("HTTPS has %d failures counted, want 0", n)
	}
}

// An answer alice's /msg takes and refuses has been judged: it is not sent
// again over DNS. It comes back not accepted, naming the mechanism that
// refused it, and nothing is counted.
func TestAnswerJudgedRefusalStays(t *testing.T) {
	me := newMechanismEnv(t, "answer-judged.example.", httpsJudges)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := me.Bob.Bridge.sendConfig(ctx, me.aliceAtBob, transport.MechanismAPI, &PeerConfigRequest{
		SenderID: me.bob, Zone: me.zone, Subtype: "upstream",
		ConfigData: map[string]string{"xfr_srcs": "127.0.0.1"}, Timestamp: time.Now(),
	})
	if err != nil || resp.Accepted || resp.Mechanism != transport.MechanismAPI || resp.Message != "not authorized" {
		t.Fatalf("a judged config: resp %+v err %v, want it not accepted over HTTPS", resp, err)
	}
	if p, n := me.posts.Load(), me.notifies.Load(); p != 1 || n != 0 {
		t.Errorf("%d POSTs and %d NOTIFYs, want 1 and 0", p, n)
	}
	if n := me.aliceAtBob.MechanismConsecutiveFails(transport.MechanismAPI); n != 0 {
		t.Errorf("HTTPS has %d failures counted, want 0", n)
	}
}

// An answer that DNS fails to deliver goes over HTTPS, where alice's /msg
// refuses it: it comes back not accepted, naming HTTPS, not as a failure to
// send. Only DNS's failure is counted.
func TestAnswerRefusedOnTheFallback(t *testing.T) {
	me := newMechanismEnv(t, "answer-judged-fallback.example.", httpsJudges)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &transport.Address{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port), Transport: "tcp"}
	ln.Close() // nothing listens there: every NOTIFY is refused
	me.aliceAtBob.SetDiscoveryAddress(dead)
	me.aliceAtBob.SetMechanismAddress("DNS", dead)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := me.Bob.Bridge.sendConfig(ctx, me.aliceAtBob, transport.MechanismDNS, &PeerConfigRequest{
		SenderID: me.bob, Zone: me.zone, Subtype: "upstream",
		ConfigData: map[string]string{"xfr_srcs": "127.0.0.1"}, Timestamp: time.Now(),
	})
	if err != nil || resp.Accepted || resp.Mechanism != transport.MechanismAPI || resp.Message != "not authorized" {
		t.Fatalf("DNS failing, HTTPS judging: resp %+v err %v, want it not accepted over HTTPS", resp, err)
	}
	if n := me.posts.Load(); n != 1 {
		t.Errorf("%d POSTs, want 1", n)
	}
	if d, a := me.aliceAtBob.MechanismConsecutiveFails(transport.MechanismDNS), me.aliceAtBob.MechanismConsecutiveFails(transport.MechanismAPI); d != 1 || a != 0 {
		t.Errorf("counts: DNS %d, HTTPS %d; want 1 and 0", d, a)
	}
}

// A confirmation that fails to deliver on its first-choice mechanism and
// goes on the other counts against the first (tdns-mp #236).
func TestConfirmFallbackCountsMechanismFailure(t *testing.T) {
	me := newMechanismEnv(t, "confirm-fail-count.example.", httpsDrops)
	me.aliceAtBob.SetMechanismState("API", transport.PeerStateOperational, "test")
	me.aliceAtBob.SetMechanismLastBeatSent("API", time.Now())
	if st, _ := me.aliceAtBob.MechanismEffectiveState("API"); st != transport.PeerStateOperational {
		t.Fatalf("before: %v, want OPERATIONAL", st)
	}

	id := queueSync(t, me.integEnv, me.zone)
	me.Bob.MsgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
		OriginatingDistID: id, OriginatingSender: me.alice, Mechanism: transport.MechanismAPI,
		Zone: ZoneName(me.zone), Status: "SUCCESS"})
	me.confirmed(t, id, transport.ConfirmSuccess)

	if got := me.aliceAtBob.MechanismConsecutiveFails("API"); got != 1 {
		t.Fatalf("ConsecutiveFails on API %d, want 1 after the confirmation fell back", got)
	}
	if st, _ := me.aliceAtBob.MechanismEffectiveState("API"); st != transport.PeerStateDegraded {
		t.Fatalf("after fallback: %v, want DEGRADED so the matrix shows the one-way pair", st)
	}
	if n := me.notifies.Load(); n != 1 {
		t.Errorf("%d NOTIFYs, want the fallback confirmation", n)
	}
}
