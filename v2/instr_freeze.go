/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The freeze (design 3.1, 3.3, 3.6, plan S6). From the moment an agent
 * agrees on a serial above its active one, until the transition is done,
 * nothing new starts for the zone: this provider's own changes are owed
 * (instr_kept.go), the leader sends nothing new to the parent, and the
 * signer starts no new rollover. Work under way finishes by the active
 * serial. A zone whose active serial this agent does not know yet is frozen
 * too, until the restart rule makes it known (S9).
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// freezeReasons are why the zone is frozen: an owner error holds it (design
// 3.6); its transition is not done (3.3); or it agrees on a serial above
// its active one (3.1, decision 94); or this agent does not know its active
// serial yet (3.4, S9). A refused newest serial with none agreed on is no
// reason: the zone is steady (3.6). A newer serial during the
// reconciliation waits for "done", and is no reason of its own.
func (z *zoneSerials) freezeReasons() []string {
	var why []string
	if z.OwnerError != "" {
		why = append(why, "owner error: "+z.OwnerError)
	}
	switch {
	case z.Active == nil:
		why = append(why, "the active serial is not known")
	case z.From != nil:
		why = append(why, fmt.Sprintf("reconciling from %d to %d", z.From.Serial, z.Active.Serial))
	case z.reconciling():
		why = append(why, fmt.Sprintf("reconciling to %d", z.Active.Serial))
	default:
		if a := z.agreeing(); a != nil {
			why = append(why, fmt.Sprintf("agreeing on %d", a.Serial))
		}
	}
	return why
}

// frozen is why zone, named in any case, is frozen; nil when it is not.
func (s *InstructionStore) frozen(zone string) []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, z := s.zoneLocked(zone); z != nil {
		return z.freezeReasons()
	}
	return nil
}

// agreedSince is when this agent came to hold the serial it agrees on for
// zone, or with none agreed on its newest; false when it holds none. A
// refused serial above the one agreed on does not move it.
func (s *InstructionStore) agreedSince(zone string) (time.Time, bool) {
	if s == nil {
		return time.Time{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, z := s.zoneLocked(zone)
	switch {
	case z == nil:
		return time.Time{}, false
	case z.agreeing() != nil:
		return z.agreeing().Since, true
	case z.highest() != nil:
		return z.highest().Since, true
	}
	return time.Time{}, false
}

// keeps: the store keeps serials for zone, named in any case.
func (s *InstructionStore) keeps(zone string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, z := s.zoneLocked(zone)
	return z != nil
}

// activeVoters are the zone's voting members under its active serial.
func (s *InstructionStore) activeVoters(zone string) []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, z := s.zoneLocked(zone); z != nil && z.Active != nil {
		_, voting := participantsOf(z.Active.Reading)
		return voting
	}
	return nil
}

// zoneFrozen is why the zone is frozen at this agent; nil when it is not.
func (conf *Config) zoneFrozen(zone string) []string {
	return conf.InternalMp.Instructions.frozen(zone)
}

// syncCause is why the leader works towards the parent, as the freeze
// reads it.
type syncCause int

const (
	syncOther syncCause = iota
	// syncDS: the DS set differs from the parent's. During a freeze the DS
	// set changes only through a rollover under way or an emergency one,
	// so the sync passes; it carries the whole delegation by the sets the
	// parts hold (design 3.1).
	syncDS
	// syncStep: a step of the reconciliation asks it (plan S12): it passes.
	syncStep
)

// syncHeld holds the leader's work towards the parent while the zone is
// frozen (design 3.1), unless it is the DS sync of a rollover; a step's own
// sync passes too (S12). A held sync is owed, and asked for when the
// transition is done. The other holds stay where they are: the catch-up's
// (membership step 5, holdLeaderSync) and the zone key's (step 7b,
// holdForZoneKey); S14 adds keyPending. Reports why the zone is frozen.
func (conf *Config) syncHeld(zone string, cause syncCause) (held bool, why string) {
	reasons := conf.zoneFrozen(zone)
	if len(reasons) == 0 || cause == syncDS || cause == syncStep {
		return false, ""
	}
	conf.InternalMp.CatchUp.oweForFreeze(ZoneName(zone))
	return true, strings.Join(reasons, "; ")
}

// syncCauseOf is the cause of a sync with the status st: the DS set, when
// it differs from the parent's.
func syncCauseOf(st tdns.DelegationSyncStatus) syncCause {
	if len(st.DSAdds) > 0 || len(st.DSRemoves) > 0 {
		return syncDS
	}
	return syncOther
}

// onFreeze is the store's word that a zone is frozen, or no longer is, or
// that the serial it agrees on moved while it stays frozen. The hold is a
// field of the hand-over (plan S11): the parts are handed the zone again,
// and while it is frozen the signer confirms its hold again, for the serial
// agreed on now. At the end of a freeze the data engine releases what the
// zone kept.
func (conf *Config) onFreeze(zone string, frozen bool) {
	conf.handOverToParts(zone)
	if frozen {
		conf.InternalMp.SignerHandover.again(zone)
		return
	}
	conf.InternalMp.SignerHandover.letHoldGo(zone)
	conf.askRelease(ZoneName(zone))
}

// holdConfirmed: the signer holds the hand-over this agent wants it to,
// which carries the hold, and its latest inventory says it holds the zone's
// key machine and arrived after this agent came to hold the serial it agrees
// on (plan S6; with none agreed on, its newest). A move of the serial agreed
// on has the signer say again what it holds (onFreeze), so an inventory from
// before it does not count. The stamp tells it as Hold; S7 counts a telling
// only with it (design 3.1, 3.7).
func (conf *Config) holdConfirmed(zone string) bool {
	since, ok := conf.InternalMp.Instructions.agreedSince(zone)
	if !ok || !conf.InternalMp.SignerHandover.holdHeld(zone) {
		return false
	}
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return false
	}
	snap := mpzd.GetLastKeyInventory()
	return snap != nil && snap.Hold && snap.Received.After(since)
}

// releaseBook is the zones whose release the data engine's queue had no
// room for: the engine's tick releases them, and takes them up.
type releaseBook struct {
	mu    sync.Mutex
	zones map[string]ZoneName // by zone, folded
}

// askRelease asks the data engine to release what the zone kept (instrDone),
// with the take-up of a zone this agent leads. A full queue leaves both to
// the engine's next own-read tick (releaseUnfrozen).
func (conf *Config) askRelease(zone ZoneName) {
	msgQs := conf.InternalMp.MsgQs
	if msgQs == nil || msgQs.SynchedDataCmd == nil {
		return
	}
	select {
	case msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "instr-done", Zone: zone}:
	default:
		r := &conf.InternalMp.releases
		r.mu.Lock()
		if r.zones == nil {
			r.zones = map[string]ZoneName{}
		}
		r.zones[canonicalName(string(zone))] = zone
		r.mu.Unlock()
		lgEngine.Warn("the data engine's queue is full; what the zone kept is released at its next tick", "zone", zone)
	}
}

// releaseUnfrozen is the data engine's tick for the lists: every zone that
// owes something and is no longer frozen releases it. It catches a release
// the engine's queue had no room for, which it also takes up, and one a
// restart came between.
func (conf *Config) releaseUnfrozen(ctx context.Context, zdr *ZoneDataRepo) {
	zones := map[string]ZoneName{}
	for _, z := range conf.InternalMp.Kept.zones(listOwed) {
		zones[z] = ZoneName(z)
	}
	for _, z := range conf.InternalMp.CatchUp.freezeOwedZones() {
		zones[canonicalName(string(z))] = z
	}
	r := &conf.InternalMp.releases
	r.mu.Lock()
	asked := r.zones
	r.zones = nil
	r.mu.Unlock()
	maps.Copy(zones, asked)
	for _, key := range slices.Sorted(maps.Keys(zones)) {
		zone := zones[key]
		if len(conf.zoneFrozen(string(zone))) > 0 {
			continue
		}
		conf.instrDone(ctx, zdr, zone)
		if _, ok := asked[key]; ok {
			go conf.takeUp(ctx, zone)
		}
	}
}

// instrDone releases what the zone kept while it was frozen, once it no
// longer is (design 3.3): this provider's own changes, in order, each
// applied to the data then and sent to the members the instructions active
// now name; then the sync with the parent that was held ("the transition is
// done"). An owed change of a provider that no longer votes in the zone is
// dropped, with those after it, and its own state is read again (membership
// step 3). Run by the data engine, which alone takes from the lists. The
// kept list, of other agents' distributions, is released at the
// activation (S8).
func (conf *Config) instrDone(ctx context.Context, zdr *ZoneDataRepo, zone ZoneName) {
	if len(conf.zoneFrozen(string(zone))) > 0 {
		return
	}
	k := conf.InternalMp.Kept
	owed := k.entries(string(zone), listOwed)
	syncOwed := conf.InternalMp.CatchUp.releaseFreezeOwed(zone)
	if len(owed) == 0 && !syncOwed {
		return
	}
	if !conf.InternalMp.Instructions.keeps(string(zone)) {
		// the zone left this agent's configuration, or its multi-provider
		// service ended, while it was frozen: nothing is released into it
		lgEngine.Info("the zone's serials are gone: what it kept is dropped", "zone", zone, "owed", len(owed))
		for _, e := range owed {
			if err := k.remove(string(zone), listOwed, e.Seq); err != nil {
				lgEngine.Error("a kept change could not be dropped", "zone", zone, "err", err)
			}
		}
		return
	}
	lgEngine.Info("the transition is done, handling what was kept", "zone", zone, "owed", len(owed))
	self := AgentId(conf.MpConfig().Identity)
	if len(owed) > 0 {
		if !votesInZone(zone, self) {
			lgEngine.Info("this provider no longer votes in the zone: its kept changes are dropped, and its own state is read again", "zone", zone, "dropped", len(owed))
			for _, e := range owed {
				if err := k.remove(string(zone), listOwed, e.Seq); err != nil {
					lgEngine.Error("a kept change could not be dropped", "zone", zone, "err", err)
				}
			}
			zdr.rereadOwnState(zone, "kept changes were dropped: this provider no longer votes in the zone")
		} else {
			for _, e := range owed {
				zu, err := e.Update.zoneUpdate(zone, self)
				if err != nil {
					lgEngine.Error("a kept change cannot be read; it is dropped", "zone", zone, "err", err)
				} else {
					answer := make(chan *AgentMsgResponse, 1)
					conf.applyLocalUpdate(ctx, zdr, &SynchedDataUpdate{Zone: zone, AgentId: self, UpdateType: "local", Update: zu, Force: e.Update.Force,
						replay: true, Response: answer})
					select {
					case a := <-answer:
						if a.Error {
							lgEngine.Warn("a kept change was released and was refused, or did not go out in full; if it was applied, `agent peer resync --push` sends it again", "zone", zone, "err", a.ErrorMsg)
						}
					default:
					}
				}
				if err := k.remove(string(zone), listOwed, e.Seq); err != nil {
					lgEngine.Error("a kept change could not be taken off its list", "zone", zone, "err", err)
				}
			}
		}
	}
	if syncOwed {
		conf.InternalMp.CatchUp.askOwed(ctx, zone)
	}
}

// takeUp is, for a zone this agent leads, what onLeaderElected runs, once
// the zone's freeze has ended: the key's set-up and the sync with the
// parent, which the freeze held (syncHeld). The set-up runs under the
// zone's key-setup lock, as an election's does, so the two never run at
// once.
func (conf *Config) takeUp(ctx context.Context, zone ZoneName) {
	lem := conf.InternalMp.LeaderElectionManager
	if lem == nil || !lem.IsLeader(zone) {
		return
	}
	err := conf.keySetupLocked(zone, func() error { return conf.leaderKeySetup(ctx, zone, true) })
	if err != nil && !errors.Is(err, errLeadMoved) && !errors.Is(err, errZoneKeyNotHeld) && !errors.Is(err, errHeldDuringTransition) {
		lgAgent.Warn("the key set-up after the transition failed; the sync waits for the key", "zone", zone, "err", err)
	}
	conf.requestDelegationSync(ctx, string(zone), "the transition is done")
}

// oweIfFrozen puts a change of this provider's own on the zone's owed list
// while the zone is frozen (design 3.1): an operator's edit, and the
// leader's CSYNC outside a step. A DNSKEY distribution after the signer's
// inventory passes: a rollover under way or an emergency one, as the
// signer starts no other. So does a step's own distribution (plan S12).
// Reports why the change is kept; "" when it goes on now.
func (conf *Config) oweIfFrozen(u *SynchedDataUpdate) (string, error) {
	if u.Inventory || u.Step {
		return "", nil
	}
	reasons := conf.zoneFrozen(string(u.Zone))
	if len(reasons) == 0 {
		return "", nil
	}
	why := strings.Join(reasons, "; ")
	if _, err := conf.InternalMp.Kept.add(string(u.Zone), listOwed, "", keptUpdateOf(u)); err != nil {
		return "", err
	}
	// a change of its own has no distribution until its release
	lgEngine.Info("a change of this provider's own is kept until the transition is done", "zone", u.Zone, "distrib", "", "why", why)
	return why, nil
}

// freezeLines are the zone's freeze as `agent parentsync status` shows it
// (plan S6): why it is frozen, with whom the agreement waits for; and what
// this agent keeps, of its own and of others' (S8). Both empty for a zone
// that is not frozen and keeps nothing.
func (conf *Config) freezeLines(zone string) (frozen, kept string) {
	reasons := conf.zoneFrozen(zone)
	if len(reasons) > 0 {
		frozen = strings.Join(reasons, "; ")
		if w := conf.agreementWaitsFor(zone); len(w) > 0 {
			frozen += ", waiting for " + strings.Join(w, ", ")
		}
	}
	var parts []string
	switch n := len(conf.InternalMp.Kept.entries(zone, listOwed)); n {
	case 0:
	case 1:
		parts = append(parts, "1 change of this provider's own")
	default:
		parts = append(parts, fmt.Sprintf("%d changes of this provider's own", n))
	}
	if conf.InternalMp.CatchUp.freezeOwed(ZoneName(zone)) {
		parts = append(parts, "the sync with the parent")
	}
	// other agents' distributions made under another serial (plan S8)
	switch n := len(conf.InternalMp.Kept.entries(zone, listKept)); n {
	case 0:
	case 1:
		parts = append(parts, "1 distribution of another agent's")
	default:
		parts = append(parts, fmt.Sprintf("%d distributions of other agents", n))
	}
	return frozen, strings.Join(parts, ", ")
}

// agreementWaitsFor names whom and what the agreement on the zone's serial
// agreed on waits for, as this agent sees it: the thaw's view (plan S7),
// this agent first when its signer has not confirmed the hold, then every
// other voting member under the active serial whose latest stamp does not
// tell what the thaw counts, then the leader's work at the parent.
func (conf *Config) agreementWaitsFor(zone string) []string {
	v, ok := conf.thawView(zone, time.Now())
	if !ok {
		return nil
	}
	out := slices.Clone(v.waits)
	if v.parent != "" {
		out = append(out, "the parent ("+v.parent+")")
	}
	return out
}

// signerHolds are the zones whose key machine the signer holds at its
// agent's word (the hand-over's hold, plan S6, S11), on disk (MPKeyHold):
// under a hold nothing new starts.
type signerHolds struct {
	mu    sync.Mutex
	hdb   *HsyncDB             // nil: in memory only
	zones map[string]time.Time // folded -> since
}

// loadSignerHolds reads the holds kept on disk, at the signer's start.
func loadSignerHolds(hdb *HsyncDB) (*signerHolds, error) {
	h := &signerHolds{hdb: hdb, zones: map[string]time.Time{}}
	if hdb == nil {
		return h, nil
	}
	hdb.Lock()
	defer hdb.Unlock()
	rows, err := hdb.DB.Query(`SELECT zonename, since FROM MPKeyHold`)
	if err != nil {
		return nil, fmt.Errorf("reading the key machine's holds: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var zone, since string
		if err := rows.Scan(&zone, &since); err != nil {
			return nil, fmt.Errorf("reading the key machine's holds: %w", err)
		}
		at, _ := time.Parse(time.RFC3339, since)
		h.zones[zone] = at
	}
	return h, rows.Err()
}

// held: the signer holds the zone's key machine.
func (h *signerHolds) held(zone string) bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.zones[canonicalName(zone)]
	return ok
}

// set holds the zone's key machine, or lets it go, on disk first. Reports
// whether that changed anything.
func (h *signerHolds) set(zone string, on bool) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	zone = canonicalName(zone)
	if _, was := h.zones[zone]; was == on {
		return false, nil
	}
	now := time.Now()
	if h.hdb != nil {
		h.hdb.Lock()
		var err error
		if on {
			_, err = h.hdb.DB.Exec(`INSERT INTO MPKeyHold (zonename, since) VALUES (?, ?) ON CONFLICT(zonename) DO NOTHING`, zone, now.UTC().Format(time.RFC3339))
		} else {
			_, err = h.hdb.DB.Exec(`DELETE FROM MPKeyHold WHERE zonename = ?`, zone)
		}
		h.hdb.Unlock()
		if err != nil {
			return false, fmt.Errorf("keeping the key machine's hold of %s: %w", zone, err)
		}
	}
	if on {
		h.zones[zone] = now
	} else {
		delete(h.zones, zone)
	}
	return true, nil
}

// signerHold is the signer's handling of its agent's hold, a field of the
// hand-over (plan S6, S11): the hold is kept, and the inventory the
// hand-over pushes confirms it.
func (conf *Config) signerHold(zone string, on bool) {
	changed, err := conf.InternalMp.SignerHolds.set(zone, on)
	if err != nil {
		lgSigner.Error("the key machine's hold could not be kept", "zone", zone, "hold", on, "err", err)
		return
	}
	if changed && on {
		lgSigner.Info("the key machine holds for the zone: nothing new starts", "zone", zone)
	} else if changed {
		lgSigner.Info("the key machine's hold for the zone ends", "zone", zone)
	}
}
