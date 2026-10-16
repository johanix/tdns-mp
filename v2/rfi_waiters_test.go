/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdnsmp

import (
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// Two zones ask the same peer for their SIG(0) key at the same time and the
// answers come back in the other order: each request gets its own zone's
// answer.
func TestRfiWaiters_ConcurrentZones(t *testing.T) {
	var w rfiWaiters[*ConfigResponseMsg]
	peer := "agent.p.example."
	ansA, cancelA := w.register(rfiWaitKey(peer, "a.example.", "sig0key"))
	defer cancelA()
	ansB, cancelB := w.register(rfiWaitKey(peer, "b.example.", "sig0key"))
	defer cancelB()

	if !w.deliver(rfiWaitKey(peer, "b.example.", "sig0key"), &ConfigResponseMsg{SenderID: peer, Zone: "b.example.", Subtype: "sig0key"}) {
		t.Fatal("answer for b.example. found no waiter")
	}
	if !w.deliver(rfiWaitKey(peer, "a.example.", "sig0key"), &ConfigResponseMsg{SenderID: peer, Zone: "a.example.", Subtype: "sig0key"}) {
		t.Fatal("answer for a.example. found no waiter")
	}

	if m, ok := recvWithin(ansA, time.Second); !ok || m.Zone != "a.example." {
		t.Errorf("request for a.example. got %+v (ok=%v)", m, ok)
	}
	if m, ok := recvWithin(ansB, time.Second); !ok || m.Zone != "b.example." {
		t.Errorf("request for b.example. got %+v (ok=%v)", m, ok)
	}
}

// An answer must match sender, zone and subtype; names compare as DNS names.
func TestRfiWaiters_Key(t *testing.T) {
	var w rfiWaiters[*ConfigResponseMsg]
	ans, cancel := w.register(rfiWaitKey("agent.p.example.", "a.example.", "sig0key"))
	defer cancel()

	for _, k := range []string{
		rfiWaitKey("agent.q.example.", "a.example.", "sig0key"),
		rfiWaitKey("agent.p.example.", "b.example.", "sig0key"),
		rfiWaitKey("agent.p.example.", "a.example.", "upstream"),
	} {
		if w.deliver(k, &ConfigResponseMsg{}) {
			t.Errorf("answer %q was taken by the request for agent.p.example. a.example. sig0key", k)
		}
	}
	if !w.deliver(rfiWaitKey("Agent.P.Example", "A.example", "sig0key"), &ConfigResponseMsg{Zone: "A.example"}) {
		t.Fatal("answer differing only in case and trailing dot found no waiter")
	}
	if _, ok := recvWithin(ans, time.Second); !ok {
		t.Error("request got no answer")
	}
}

// Requests with the same key get the answers in the order they asked; an
// answer after the last request is done finds no one.
func TestRfiWaiters_SameKeyAndLateAnswer(t *testing.T) {
	var w rfiWaiters[*AuditResponseMsg]
	key := rfiWaitKey("agent.p.example.", "a.example.", "")
	first, cancelFirst := w.register(key)
	second, cancelSecond := w.register(key)

	w.deliver(key, &AuditResponseMsg{AuditData: 1})
	w.deliver(key, &AuditResponseMsg{AuditData: 2})
	if m, ok := recvWithin(first, time.Second); !ok || m.AuditData != 1 {
		t.Errorf("first request got %+v (ok=%v)", m, ok)
	}
	if m, ok := recvWithin(second, time.Second); !ok || m.AuditData != 2 {
		t.Errorf("second request got %+v (ok=%v)", m, ok)
	}
	cancelFirst()
	cancelSecond()

	// A request that timed out (cancelled without an answer) leaves no trace.
	_, cancelTimedOut := w.register(key)
	cancelTimedOut()
	if w.deliver(key, &AuditResponseMsg{}) {
		t.Error("late answer was taken although no request waits")
	}
	if len(w.waiting) != 0 {
		t.Errorf("waiters left behind: %v", w.waiting)
	}
}

// A peer's key whose KEY RR belongs to another name is refused before it
// reaches the keystore.
func TestImportSig0KeyFromPeer_WrongOwner(t *testing.T) {
	key := &dns.KEY{DNSKEY: dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "b.example.", Rrtype: dns.TypeKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pem, err := tdns.PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM: %v", err)
	}
	configData := map[string]string{"algorithm": "ED25519", "privatekey": pem, "keyrr": key.String()}

	// hdb is nil: the check must refuse before the keystore is touched.
	err = importSig0KeyFromPeer(nil, "a.example.", configData)
	if err == nil || !strings.Contains(err.Error(), "not a KEY for") {
		t.Fatalf("import of b.example.'s key as a.example.: err = %v, want a refusal", err)
	}
}
