/*
 * RFI CONFIG/AUDIT answers prefer the request's mechanism (#238), and a
 * confirmation that falls back counts against the first-choice mechanism
 * (#236).
 */

package tdnsmp

import (
	"context"
	"errors"
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
	if err != nil || !resp.Accepted {
		t.Fatalf("config over API: resp %+v err %v", resp, err)
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
	if err != nil || !aresp.Accepted {
		t.Fatalf("audit over API: resp %+v err %v", aresp, err)
	}
	if me.posts.Load()-beforePosts != 1 || me.notifies.Load()-beforeNotifies != 0 {
		t.Errorf("audit: POSTs delta %d NOTIFYs delta %d, want 1 and 0",
			me.posts.Load()-beforePosts, me.notifies.Load()-beforeNotifies)
	}
}

// A confirmation that fails on its first-choice mechanism and goes on the
// other counts against the first (tdns-mp #236).
func TestConfirmFallbackCountsMechanismFailure(t *testing.T) {
	me := newMechanismEnv(t, "confirm-fail-count.example.", httpsRefuses)
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

	if got := me.aliceAtBob.MechanismConsecutiveFails("API"); got < 1 {
		t.Fatalf("ConsecutiveFails on API %d, want at least 1 after confirm fallback", got)
	}
	if st, _ := me.aliceAtBob.MechanismEffectiveState("API"); st != transport.PeerStateDegraded {
		t.Fatalf("after fallback: %v, want DEGRADED so the matrix shows the one-way pair", st)
	}
	if n := me.notifies.Load(); n != 1 {
		t.Errorf("%d NOTIFYs, want the fallback confirmation", n)
	}
}
