/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The leader's sync waits for the zone's SIG(0) key (step 7b, settle point 1).
//
// tdns signs the leader's UPDATE with the first active key row, and on BADKEY
// uploads that key to the parent as a bootstrap, without waiting for the key
// to be served. A sync signed with a key the parent does not trust yet, or
// with a key that is not the zone's, starts that. So the leader's sync of a
// zone that uses a key waits while
//
//   - the key tdns would sign with is not the zone's key (readZoneKey), or
//     there is not exactly one active key; or
//   - a poll of the zone's key with its parent runs in this process
//     (ParentSyncAfterKeyPublication): it bootstraps the key once the key
//     is served, and the sync signed with it waits for that; or
//   - a key this agent made or took was not published.
//
// The held sync is owed, and asked for when the hold ends: when the last
// poll of the zone's key ends (keyPollEnded), when the key is retired to one,
// and from the 30 s ticker (retestKeyHolds).

// keyPollBook is the per-zone state of the hold, under its own lock: a leaf,
// taken by nothing that holds another lock of this package's.
type keyPollBook struct {
	mu sync.Mutex
	// running: the polls that run, and the set-ups that are about to start
	// one (a key being made or taken counts from before it is made).
	running map[ZoneName]int
	// unpublished: a key made or taken whose publication failed. The zone
	// stays held until a later set-up publishes the key and starts a poll.
	unpublished map[ZoneName]bool
	// ended: the zone's key whose poll last ended in this process, and the
	// lead it ran in (LeaderElectionManager.LeadStart). A renewal of that
	// lead neither publishes the key again nor starts another poll.
	ended map[ZoneName]keyPollEnd
	// owed: zones held with no catch-up tracker to keep the owed mark.
	owed map[ZoneName]bool
	// logged: when the hold was last logged for the zone (once an hour).
	logged map[ZoneName]time.Time
	// retesting: a backstop pass runs (retestKeyHoldsInBackground).
	retesting atomic.Bool
}

type keyPollEnd struct {
	keyid     uint16
	leadStart uint64
}

func (b *keyPollBook) init() {
	if b.running == nil {
		b.running = map[ZoneName]int{}
		b.unpublished = map[ZoneName]bool{}
		b.ended = map[ZoneName]keyPollEnd{}
		b.owed = map[ZoneName]bool{}
		b.logged = map[ZoneName]time.Time{}
	}
}

func canonZone(zone ZoneName) ZoneName { return ZoneName(dns.CanonicalName(string(zone))) }

// keyPollToken is one count of a zone in running: taken before a key is made
// or taken, and handed to the poll that the set-up starts, or given back.
type keyPollToken struct {
	b      *keyPollBook
	zone   ZoneName
	once   sync.Once
	handed bool
}

// begin counts a set-up of the zone's key that may start a poll.
func (b *keyPollBook) begin(zone ZoneName) *keyPollToken {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	zone = canonZone(zone)
	b.running[zone]++
	return &keyPollToken{b: b, zone: zone}
}

// end gives the count back, unless a poll took it. With unpublished, the key
// made or taken was not published: the zone stays held.
func (tk *keyPollToken) end(unpublished bool) int {
	if tk == nil {
		return 0
	}
	left := -1
	tk.once.Do(func() {
		if tk.handed {
			return
		}
		b := tk.b
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.running[tk.zone] > 0 {
			b.running[tk.zone]--
		}
		if unpublished {
			b.unpublished[tk.zone] = true
		}
		left = b.running[tk.zone]
	})
	return left
}

// published notes that the zone's key is published: an earlier failure no
// longer holds the zone.
func (b *keyPollBook) published(zone ZoneName) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	delete(b.unpublished, canonZone(zone))
}

// pollEnded ends a poll, and says how many still run. A poll that ran to its
// end in the lead it started in notes the key and that lead (finished): a
// renewal of the lead keeps the key. One that returned because the lead
// moved notes nothing: the poll did not run to its end, and a later lead,
// or the same one taking the zone up again, polls anew.
func (b *keyPollBook) pollEnded(zone ZoneName, keyid uint16, leadStart uint64, finished bool) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	zone = canonZone(zone)
	if b.running[zone] > 0 {
		b.running[zone]--
	}
	if finished {
		b.ended[zone] = keyPollEnd{keyid: keyid, leadStart: leadStart}
	}
	return b.running[zone]
}

// state is what the hold reads of the zone.
func (b *keyPollBook) state(zone ZoneName) (running int, unpublished bool, ended keyPollEnd) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.init()
	zone = canonZone(zone)
	return b.running[zone], b.unpublished[zone], b.ended[zone]
}

// renewalKeepsKey: the lead is the one the zone's key was last polled in, in
// this process, and the key is the zone's, published. A renewal then
// neither publishes the key again nor starts a poll, whatever that poll's
// outcome: a parent that has lost trust in the key shows as BADKEY at the
// next sync. A new lead (leadStart differs), a new or taken key, and a
// restart (nothing ended in this process) publish and poll.
func renewalKeepsKey(zk *zoneKey, ended keyPollEnd, leadStart uint64) bool {
	return zk != nil && zk.held != nil && leadStart != 0 && ended.leadStart == leadStart &&
		ended.keyid == zk.held.keyid && len(zk.published) == 1 && sameKey(zk.published[0], zk.held.key)
}

// zoneUsesKey: the zone syncs with its parent through its agents
// (parentsync=agent) and the parent advertises the DSYNC UPDATE scheme. For
// any other zone nothing of the key's hold applies: a parent that takes
// NOTIFY only needs no SIG(0) key. A zone whose parent cannot be asked (no
// resolver) uses none here.
func (conf *Config) zoneUsesKey(ctx context.Context, zone ZoneName) bool {
	mpzd, ok := Zones.Get(string(zone))
	if !ok || mpzd == nil || mpzd.ZoneData == nil || !mpzd.Options[tdns.OptParentSync] {
		return false
	}
	if conf.Config == nil || conf.Config.Internal.ImrEngine == nil {
		return false
	}
	imr := &Imr{conf.Config.Internal.ImrEngine}
	_, err := imr.LookupDSYNCTarget(ctx, string(zone), dns.TypeANY, core.SchemeUpdate)
	return err == nil
}

// zoneKeyUse is zoneUsesKey for the key rounds, which must not read a
// failed look-up as "no key needed": a voting member that stopped asking
// would hold no key until the next KEY change. known is false when the
// parent's DSYNC records could not be read (no resolver yet, a failed
// look-up); then the rounds go on asking, and no key is made.
func (conf *Config) zoneKeyUse(ctx context.Context, zone ZoneName) (uses, known bool) {
	mpzd, ok := Zones.Get(string(zone))
	if !ok || mpzd == nil || mpzd.ZoneData == nil || !mpzd.Options[tdns.OptParentSync] {
		return false, true
	}
	if conf.Config == nil || conf.Config.Internal.ImrEngine == nil {
		return false, false
	}
	imr := &Imr{conf.Config.Internal.ImrEngine}
	res, err := imr.DsyncDiscovery(ctx, string(zone), false)
	if err != nil {
		return false, false
	}
	for _, d := range res.Rdata {
		if d != nil && d.Scheme == core.SchemeUpdate && d.Type == dns.TypeANY && d.Usable() {
			return true, true
		}
	}
	return false, true
}

// keyHoldReason says why the leader's sync of the zone waits for the zone's
// key, or "" when it does not. It reads the keystore and asks the resolver:
// never called under a lock of the catch-up tracker. It does not read tdns's
// cache of the keys it signs with (KeystoreSig0Cache), a map tdns keeps no
// lock around: only the syncher's own goroutine, where tdns signs, reads it
// (signingKeyCached).
func (conf *Config) keyHoldReason(ctx context.Context, zone ZoneName) string {
	_, why := conf.keyHold(ctx, zone)
	return why
}

// keyHold is keyHoldReason, and whether the zone uses a key at all.
func (conf *Config) keyHold(ctx context.Context, zone ZoneName) (uses bool, why string) {
	if !conf.zoneUsesKey(ctx, zone) {
		return false, ""
	}
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return true, "not held"
	}
	zk, err := readZoneKey(kdb, zone)
	if err != nil || zk.held == nil {
		return true, "not held"
	}
	if len(zk.active) != 1 {
		return true, "signing key differs"
	}
	running, unpublished, _ := conf.InternalMp.keyPolls.state(zone)
	if running > 0 {
		return true, "poll running"
	}
	if unpublished {
		return true, "not published"
	}
	return true, ""
}

// holdForZoneKey holds the leader's sync of a multi-provider zone while the
// zone's key is not held, not the one tdns signs with, or still being
// bootstrapped: it marks the sync owed for the key, logs why (the first time
// and then once an hour), and reports that nothing is to be sent. The
// syncher calls it after the hold for the catch-up, in both arms; the
// explicit arm answers its caller at once. Never waits.
func (conf *Config) holdForZoneKey(ctx context.Context, ds tdns.DelegationSyncRequest) (held bool, why string) {
	if !mpLeaderSync(conf, ds) {
		return false, ""
	}
	zone := ZoneName(ds.ZoneName)
	uses, why := conf.keyHold(ctx, zone)
	if uses && why == "" && !conf.signingKeyCached(zone) {
		why = "signing key differs"
	}
	if why == "" {
		return false, ""
	}
	if t := conf.InternalMp.CatchUp; t != nil {
		t.oweForKey(zone)
	} else {
		b := &conf.InternalMp.keyPolls
		b.mu.Lock()
		b.init()
		b.owed[canonZone(zone)] = true
		b.mu.Unlock()
	}
	b := &conf.InternalMp.keyPolls
	b.mu.Lock()
	b.init()
	last := b.logged[canonZone(zone)]
	now := time.Now()
	logIt := now.Sub(last) >= time.Hour
	if logIt {
		b.logged[canonZone(zone)] = now
	}
	b.mu.Unlock()
	if logIt {
		lgAgent.Info("the sync with the parent waits for the zone's SIG(0) key", "zone", zone, "reason", why)
	}
	return true, why
}

// signingKeyCached: the key tdns signs the zone's UPDATE with, read through
// its cache as tdns reads it (GetSig0Keys), is the zone's only active key. A
// cache that still holds a retired key (tdns #943) is cleared once, and read
// again. Called on the syncher's goroutine only, where tdns signs: the cache
// is a map tdns keeps no lock around.
func (conf *Config) signingKeyCached(zone ZoneName) bool {
	kdb := conf.zoneKeyDB(zone)
	if kdb == nil {
		return false
	}
	active, err := activeSig0Rows(kdb, zone)
	if err != nil || len(active) != 1 {
		return false
	}
	for try := 0; try < 2; try++ {
		sak, err := kdb.GetSig0Keys(dns.Fqdn(string(zone)), tdns.Sig0StateActive)
		if err == nil && sak != nil && len(sak.Keys) > 0 && sak.Keys[0].KeyId == active[0].keyid {
			return true
		}
		delete(kdb.KeystoreSig0Cache, dns.Fqdn(string(zone))+"+"+tdns.Sig0StateActive)
	}
	return false
}

// releaseKeyHold asks for the sync held for the zone's key, when the key's
// hold is over. The catch-up's hold, if any, keeps it owed. Called outside
// every lock of the tracker's.
func (conf *Config) releaseKeyHold(ctx context.Context, zone ZoneName) {
	if why := conf.keyHoldReason(ctx, zone); why != "" {
		return
	}
	if t := conf.InternalMp.CatchUp; t != nil {
		if t.releaseKeyOwed(zone) {
			lgAgent.Info("the zone's SIG(0) key is held and bootstrapped, asking for the sync that waited", "zone", zone)
			t.askOwed(ctx, zone)
		}
		return
	}
	b := &conf.InternalMp.keyPolls
	b.mu.Lock()
	b.init()
	owed := b.owed[canonZone(zone)]
	delete(b.owed, canonZone(zone))
	b.mu.Unlock()
	if owed {
		lgAgent.Info("the zone's SIG(0) key is held and bootstrapped, asking for the sync that waited", "zone", zone)
		conf.askOwedDelegationSync(ctx, zone)
	}
}

// retestKeyHolds releases every key hold that is over: the backstop, from
// the 30 s ticker.
func (conf *Config) retestKeyHolds(ctx context.Context) {
	zones := conf.InternalMp.CatchUp.keyOwedZones()
	b := &conf.InternalMp.keyPolls
	b.mu.Lock()
	b.init()
	for zone := range b.owed {
		zones = append(zones, zone)
	}
	b.mu.Unlock()
	for _, zone := range zones {
		conf.releaseKeyHold(ctx, zone)
	}
}

// retestKeyHoldsInBackground runs retestKeyHolds on a goroutine of its own,
// one at a time.
func (conf *Config) retestKeyHoldsInBackground(ctx context.Context) {
	b := &conf.InternalMp.keyPolls
	if !b.retesting.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer b.retesting.Store(false)
		conf.retestKeyHolds(ctx)
	}()
}

// launchKeyPoll starts the poll of the zone's key with its parent, counted in
// keyPolls until it returns; a token, when given, is the count the set-up
// took before it made or took the key. The sync of the zone waits while the
// poll runs, and when the last poll of the zone ends the sync that waited is
// asked for. The operator's parentsync-bootstrap starts its poll here too.
func (conf *Config) launchKeyPoll(ctx context.Context, tk *keyPollToken, zone ZoneName, keyName string, keyid uint16, algorithm uint8) {
	b := &conf.InternalMp.keyPolls
	if tk == nil {
		tk = b.begin(zone)
	}
	tk.handed = true
	var leadStart uint64
	if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
		leadStart = lem.LeadStart(zone)
	}
	go func() {
		defer func() {
			// finished: this agent still leads the zone in the lead the
			// poll started in
			finished := true
			if lem := conf.InternalMp.LeaderElectionManager; lem != nil {
				finished = leadStart != 0 && lem.LeadStart(zone) == leadStart
			}
			if left := b.pollEnded(zone, keyid, leadStart, finished); left == 0 {
				conf.releaseKeyHold(ctx, zone)
			}
		}()
		conf.ParentSyncAfterKeyPublication(ctx, zone, keyName, keyid, algorithm)
	}()
}
