/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// keyHoldRig is the hold rig on a parent that takes UPDATE, with the zone's
// key made, the zone caught up, and tdns's poll replaced by one that runs
// until released.
type keyHoldRig struct {
	*holdRig
	zone    ZoneName
	key     sig0Row
	entered chan struct{}
	release chan struct{}
}

func newKeyHoldRig(t *testing.T, zone string) *keyHoldRig {
	t.Helper()
	h := newHoldRig(t, zone, "UPDATE", false, repeat(time.Hour, 4)...)
	r := &keyHoldRig{holdRig: h, zone: ZoneName(h.mpzd.ZoneName), entered: make(chan struct{}, 4), release: make(chan struct{})}
	r.key = testSig0Key(t, h.mpzd.KeyDB, h.mpzd.ZoneName)
	h.conf.InternalMp.keyPoll = func(ctx context.Context, _ ZoneName, _ string, _ uint16, _ uint8) {
		r.entered <- struct{}{}
		select {
		case <-r.release:
		case <-ctx.Done():
		}
	}
	h.parent.holdsNS("ns1."+h.mpzd.ZoneName, h.oldNS) // the parent has an NS the zone no longer lists
	h.caughtUp()
	return r
}

// pollRuns starts the poll of the zone's key, and waits until it runs.
func (r *keyHoldRig) pollRuns(t *testing.T) {
	t.Helper()
	r.conf.launchKeyPoll(r.ctx, nil, r.zone, string(r.zone), r.key.keyid, r.key.key.Algorithm)
	select {
	case <-r.entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("the key poll did not run\n%s", r.log)
	}
}

func (r *keyHoldRig) explicit(t *testing.T) tdns.DelegationSyncStatus {
	t.Helper()
	resp := make(chan tdns.DelegationSyncStatus, 1)
	r.q <- tdns.DelegationSyncRequest{Command: "EXPLICIT-SYNC-DELEGATION", ZoneName: string(r.zone), ZoneData: r.mpzd.ZoneData, Response: resp}
	got, ok := recvWithin(resp, 2*time.Second)
	if !ok {
		t.Fatalf("the explicit sync got no answer: the syncher waited\n%s", r.log)
	}
	return got
}

func (r *keyHoldRig) keyOwed() bool {
	r.tr.mu.Lock()
	defer r.tr.mu.Unlock()
	o := r.tr.owed[ZoneName(dns.Fqdn(string(r.zone)))]
	return o != nil && o.key
}

// While a poll of the zone's key runs, the leader's sync waits. An explicit
// sync is answered at once, the key poll's own one after the parent trusts
// the key included: never left waiting until the poll ends. The sync is
// owed for the key; the catch-up does not release it. When the poll ends,
// the sync that waited is asked for, and goes out.
func TestASyncHeldForTheKeyPollIsAnsweredAtOnceAndAskedForAtItsEnd(t *testing.T) {
	r := newKeyHoldRig(t, "polled.key.example.")
	r.pollRuns(t)

	got := r.explicit(t)
	if !strings.Contains(got.Msg, "waits for the zone's SIG(0) key (poll running)") {
		t.Errorf("the explicit sync's answer: %q", got.Msg)
	}
	if !r.keyOwed() {
		t.Fatal("the held sync is not owed for the key")
	}
	r.askOwed() // what the catch-up's places do
	if !r.keyOwed() {
		t.Fatal("the catch-up's ask released the sync held for the key")
	}
	time.Sleep(200 * time.Millisecond)
	if n := r.parent.updatesSeen(); n != 0 {
		t.Fatalf("%d UPDATEs reached the parent while the key's poll ran", n)
	}

	close(r.release)
	waitUntil(t, "the sync that waited for the key went out\n"+r.log.String(), func() bool { return r.parent.updatesSeen() > 0 })
	if r.keyOwed() {
		t.Error("the sync is still owed for the key after the poll ended")
	}
}

// The implicit sync of a refresh is held the same way.
func TestARefreshsSyncIsHeldWhileTheKeyPollRuns(t *testing.T) {
	r := newKeyHoldRig(t, "polled.refresh.example.")
	r.pollRuns(t)
	r.q <- tdns.DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: string(r.zone), ZoneData: r.mpzd.ZoneData,
		SyncStatus: tdns.DelegationSyncStatus{ZoneName: string(r.zone)}}
	waitUntil(t, "the refresh's sync was not owed for the key\n"+r.log.String(), r.keyOwed)
	if n := r.parent.updatesSeen(); n != 0 {
		t.Fatalf("%d UPDATEs reached the parent while the key's poll ran", n)
	}
	close(r.release)
	waitUntil(t, "the sync that waited for the key went out\n"+r.log.String(), func() bool { return r.parent.updatesSeen() > 0 })
}

// The sync waits while the key tdns signs with is not the zone's only active
// key, and goes out once the others are retired.
func TestTheSyncWaitsUntilTheZonesKeyIsTheOnlyActiveOne(t *testing.T) {
	r := newKeyHoldRig(t, "two.keys.example.")
	testSig0Key(t, r.mpzd.KeyDB, string(r.zone))

	if got := r.explicit(t); !strings.Contains(got.Msg, "(signing key differs)") {
		t.Fatalf("with two active keys the explicit sync's answer: %q", got.Msg)
	}
	zk, err := readZoneKey(r.mpzd.KeyDB, r.zone)
	if err != nil || zk.held == nil {
		t.Fatalf("the zone's key: %+v, %v", zk, err)
	}
	if only, err := retireOtherActiveKeys(r.mpzd.KeyDB, r.zone, zk); !only || err != nil {
		t.Fatalf("retire: %v, %v", only, err)
	}
	r.conf.releaseKeyHold(r.ctx, r.zone)
	waitUntil(t, "the sync that waited for the key went out\n"+r.log.String(), func() bool { return r.parent.updatesSeen() > 0 })
}

// A renewal of the lead in which the zone's key was polled, the key
// published, publishes nothing again and starts no poll. A new lead, another
// key, an unpublished one and a restart (nothing ended here) do.
func TestARenewalKeepsTheZonesKeyAsItIs(t *testing.T) {
	const zone = "renewal.keeps.example."
	kdb := newMPTestKeyDB(t)
	k := testSig0Key(t, kdb, zone)
	other := testSig0Key(t, newMPTestKeyDB(t), zone)
	keyZone(t, zone, k)
	zk, err := readZoneKey(kdb, zone)
	if err != nil || zk.held == nil {
		t.Fatalf("the zone's key: %v", err)
	}
	unpublished := &zoneKey{held: zk.held, active: zk.active}
	for _, c := range []struct {
		name      string
		zk        *zoneKey
		ended     keyPollEnd
		leadStart uint64
		keeps     bool
	}{
		{"a renewal", zk, keyPollEnd{k.keyid, 5}, 5, true},
		{"a new lead", zk, keyPollEnd{k.keyid, 5}, 7, false},
		{"another key polled", zk, keyPollEnd{other.keyid, 5}, 5, false},
		{"after a restart", zk, keyPollEnd{}, 5, false},
		{"not leading", zk, keyPollEnd{k.keyid, 5}, 0, false},
		{"the key not published", unpublished, keyPollEnd{k.keyid, 5}, 5, false},
	} {
		if got := renewalKeepsKey(c.zk, c.ended, c.leadStart); got != c.keeps {
			t.Errorf("%s: keeps the key %v, want %v", c.name, got, c.keeps)
		}
	}
}

// The term a lead began in: a renewal keeps it, another agent's lead clears
// it, a lead after another's or after a lapsed lease starts anew.
func TestALeadStartsAtItsFirstTermAndARenewalKeepsIt(t *testing.T) {
	lem := &LeaderElectionManager{localID: "us.example."}
	le := &LeaderElection{}
	lead := func(leader AgentId, term uint64, lease time.Duration) uint64 {
		le.Term = term
		now := time.Now()
		lem.noteLeaderLocked(le, leader, now)
		le.Leader, le.LeaderExpiry = leader, now.Add(lease)
		return le.leadStart
	}
	if got := lead("us.example.", 1, time.Hour); got != 1 {
		t.Errorf("a first lead starts at %d, want 1", got)
	}
	if got := lead("us.example.", 2, time.Hour); got != 1 {
		t.Errorf("a renewal starts the lead at %d, want 1", got)
	}
	if got := lead("them.example.", 3, time.Hour); got != 0 {
		t.Errorf("another agent's lead leaves %d, want 0", got)
	}
	if got := lead("us.example.", 4, -time.Second); got != 4 {
		t.Errorf("a lead after another's starts at %d, want 4", got)
	}
	if got := lead("us.example.", 5, time.Hour); got != 5 {
		t.Errorf("a lead after a lapsed lease starts at %d, want 5", got)
	}
}

// BADKEY with no active key makes no key (1c): tdns's re-bootstrap passes
// algorithm 0, which generation refuses.
func TestABadkeyWithNoActiveKeyMakesNoKey(t *testing.T) {
	const zone = "badkey.nokey.example."
	kdb := newMPTestKeyDB(t)
	zd := &tdns.ZoneData{ZoneName: zone, KeyDB: kdb, Logger: log.New(io.Discard, "", 0), Options: map[tdns.ZoneOption]bool{}}
	zd.SetParent("example.")
	if _, _, err := zd.BootstrapSig0KeyWithParent(context.Background(), 0); err == nil {
		t.Error("the bootstrap with no active key and algorithm 0 did not fail")
	}
	rows, err := kdb.Query(`SELECT count(*) FROM Sig0KeyStore WHERE zonename=?`, zone)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var n int
	if rows.Next() {
		_ = rows.Scan(&n)
	}
	if n != 0 {
		t.Errorf("BADKEY with no active key left %d SIG(0) key(s) in the keystore, want none", n)
	}
}
