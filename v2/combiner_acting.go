/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The combiner's side of the hand-over (plan S10; acting_handover.go is the
 * agent's): the serial, the instructions and the sets its agent handed it,
 * kept in HsyncDB (MPActingSerial) and read before the zones' first load.
 * Every reader of a zone's instructions at the combiner reads them
 * (instructionsFor, mpzd.instructions and mpzd.roles), for the zone as
 * served and for a copy being analysed alike, so a refresh no longer moves
 * what the combiner acts by. A combiner handed nothing for a zone acts by
 * its own copy (rule 5): provisional for a copy that carries no serial, and
 * waiting for its agent for one that does. Until S7 a copy with a newer
 * serial than the one handed is acted by (actsBy).
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// actingStore is what a combiner holds of each zone's hand-over, by zone.
type actingStore struct {
	mu    sync.Mutex
	hdb   *HsyncDB // nil: in memory only
	zones map[string]*heldHandover
}

type heldHandover struct {
	handover *ActingHandover
	reading  *Instructions // the handover's records, read
	by       string        // the agent that handed it
	since    time.Time
}

// actingHeld is the combiner's store of hand-overs, set by its
// initialisation; nil on every other role, and in a test that sets none.
var actingHeld atomic.Pointer[actingStore]

// errHandoverOlder: a hand-over below the one held, by the order key.
var errHandoverOlder = errors.New("older than the hand-over held")

// handoverKey is the key a zone's hand-over is kept under, at the agent and
// the combiner alike.
func handoverKey(zone string) string { return core.CanonicalizeName(dns.Fqdn(zone)) }

// loadActingStore reads the hand-overs the combiner holds. A row whose
// records no longer read, or give another digest, is dropped with a log
// line: the zone waits for its agent's hand-over.
func loadActingStore(hdb *HsyncDB) (*actingStore, error) {
	s := &actingStore{hdb: hdb, zones: map[string]*heldHandover{}}
	if hdb == nil {
		return s, nil
	}
	hdb.Lock()
	defer hdb.Unlock()
	if _, err := hdb.DB.Exec(HsyncTables["MPActingSerial"]); err != nil {
		return nil, fmt.Errorf("the MPActingSerial table: %w", err)
	}
	rows, err := hdb.DB.Query(`SELECT zonename, handover, handed_by, since FROM MPActingSerial`)
	if err != nil {
		return nil, fmt.Errorf("reading the hand-overs held: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var zone, js, by, since string
		if err := rows.Scan(&zone, &js, &by, &since); err != nil {
			return nil, fmt.Errorf("reading the hand-overs held: %w", err)
		}
		h := &ActingHandover{}
		if err := json.Unmarshal([]byte(js), h); err != nil {
			lgCombiner.Error("a stored hand-over does not decode; the zone waits for its agent's", "zone", zone, "err", err)
			continue
		}
		in, err := h.read()
		if err != nil {
			lgCombiner.Error("a stored hand-over does not read; the zone waits for its agent's", "zone", zone, "err", err)
			continue
		}
		at, _ := time.Parse(time.RFC3339, since)
		s.zones[handoverKey(zone)] = &heldHandover{handover: h, reading: in, by: by, since: at}
	}
	return s, rows.Err()
}

// read is the hand-over's records, read, checked against the serial and
// the digest it names; nil for a hand-over of no instructions.
func (h *ActingHandover) read() (*Instructions, error) {
	if len(h.Records) == 0 {
		return nil, nil
	}
	in, err := readInstructionRecords(h.Zone, h.Records)
	if err != nil {
		return nil, fmt.Errorf("its records do not read: %w", err)
	}
	if in == nil || in.Serial != h.Serial || in.Digest() != h.Digest {
		got := "nothing"
		if in != nil {
			got = fmt.Sprintf("%d (%s)", in.Serial, in.Digest())
		}
		return nil, fmt.Errorf("its records give %s, not the %d (%s) it names", got, h.Serial, h.Digest)
	}
	return in, nil
}

func (s *actingStore) get(zone string) (heldHandover, bool) {
	if s == nil {
		return heldHandover{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if held := s.zones[handoverKey(zone)]; held != nil {
		return *held, true
	}
	return heldHandover{}, false
}

// actsBy is the hand-over the combiner acts by for the zone, given the apex
// of its own copy (the zone as served, or a copy being analysed): the one it
// holds, unless that copy carries a newer serial (RFC 1982; a copy with no
// serial is not newer). Until S7 the
// agent's serial follows its own copy, which it takes from its signer, and
// the signer from this combiner: at every edit the hand-over trails this
// combiner's copy by two transfers, and in that gap the combiner acts by its
// copy, as before S10. A combiner whose copy lags its agent's acts by the
// agent's. S7, which gives the agent serials it refuses, removes the rule.
func (s *actingStore) actsBy(zone string, apex *tdns.OwnerData) (heldHandover, bool) {
	held, ok := s.get(zone)
	if !ok {
		return heldHandover{}, false
	}
	if own := readingOf(apex); own != nil && own.Serial != 0 && CompareSerial(own.Serial, held.handover.Serial) == 1 {
		return heldHandover{}, false
	}
	return held, true
}

// reading is the instructions the combiner was handed for the zone and acts
// by (actsBy); nil when it acts by the copy at apex.
func (s *actingStore) reading(zone string, apex *tdns.OwnerData) *Instructions {
	held, ok := s.actsBy(zone, apex)
	if !ok {
		return nil
	}
	return held.reading
}

// roles are the sets the combiner was handed for the zone, and whether it
// acts by them (actsBy).
func (s *actingStore) roles(zone string, apex *tdns.OwnerData) (Roles, bool) {
	held, ok := s.actsBy(zone, apex)
	if !ok {
		return Roles{}, false
	}
	return held.handover.Sets, true
}

// signingSet is the handed set of who signs, as the signing set
// populateMPdata reads (#275), and whether the combiner acts by it.
func (s *actingStore) signingSet(zone string, apex *tdns.OwnerData) (signingSet, bool) {
	r, ok := s.roles(zone, apex)
	if !ok {
		return nil, false
	}
	set := signingSet{}
	for _, p := range r.Signing {
		set[p.Label] = p.Identity
	}
	return set, true
}

// take stores a hand-over from the agent by: refused when its records do not
// give the serial and digest it names, or when it is older than the one held
// (errHandoverOlder, with the one held). A hand-over of no instructions drops
// what is held: the combiner acts by its copy. changed says that what the
// combiner acts by changed; prev is what it held before. Stored before it
// returns, so before it is confirmed.
func (s *actingStore) take(h *ActingHandover, by string) (prev *ActingHandover, changed bool, err error) {
	in, err := h.read()
	if err != nil {
		return nil, false, err
	}
	key := handoverKey(h.Zone)
	stored := *h
	stored.Refresh = false
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur := s.zones[key]; cur != nil {
		prev = cur.handover
		if h.olderThan(cur.handover) {
			return prev, false, errHandoverOlder
		}
		if h.sameAs(cur.handover) {
			return prev, false, nil
		}
	}
	if in == nil {
		if prev == nil {
			return nil, false, nil
		}
		if s.hdb != nil {
			s.hdb.Lock()
			_, err := s.hdb.DB.Exec(`DELETE FROM MPActingSerial WHERE zonename=?`, key)
			s.hdb.Unlock()
			if err != nil {
				return prev, false, fmt.Errorf("dropping the hand-over held: %w", err)
			}
		}
		delete(s.zones, key)
		return prev, true, nil
	}
	now := time.Now()
	if s.hdb != nil {
		js, err := json.Marshal(&stored)
		if err != nil {
			return prev, false, err
		}
		s.hdb.Lock()
		_, err = s.hdb.DB.Exec(`INSERT INTO MPActingSerial (zonename, serial, digest, handover, handed_by, since) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(zonename) DO UPDATE SET serial=excluded.serial, digest=excluded.digest, handover=excluded.handover, handed_by=excluded.handed_by, since=excluded.since`,
			key, h.Serial, h.Digest, string(js), by, now.Format(time.RFC3339))
		s.hdb.Unlock()
		if err != nil {
			return prev, false, fmt.Errorf("keeping the hand-over: %w", err)
		}
	}
	s.zones[key] = &heldHandover{handover: &stored, reading: in, by: by, since: now}
	return prev, true, nil
}

// ownAgent: sender is one of the combiner's agents (its agents: list; the
// config check allows one).
func ownAgent(localAgents map[string]bool, sender string) bool {
	for id := range localAgents {
		if core.EqualNames(dns.Fqdn(id), dns.Fqdn(sender)) {
			return true
		}
	}
	return false
}

// combinerTakeHandover is the combiner's side of a hand-over: taken only
// from its own agent, directly, never kept for manual approval or as a
// pending edit. A hand-over whose records do not give its digest, or older
// than the one held, is refused, with what is held. Taken, the combiner
// acts by it at once: it recomputes its multi-provider data and edit
// rights, merges the stored contributions again by origin and combines.
func (conf *Config) combinerTakeHandover(msg *AgentMsgPostPlus, localAgents map[string]bool) *CombinerSyncResponse {
	h := msg.Acting
	zone := dns.Fqdn(string(msg.Zone))
	sender := string(msg.OriginatorID)
	resp := &CombinerSyncResponse{DistributionID: msg.DistributionID, Zone: zone, Nonce: msg.Nonce, Timestamp: time.Now()}
	refuse := func(why string) *CombinerSyncResponse {
		lgCombiner.Warn("refusing a hand-over", "zone", zone, "sender", sender, "reason", why)
		resp.Status, resp.Message = "error", "hand-over refused: "+why
		return resp
	}
	if !ownAgent(localAgents, sender) || (msg.DeliveredBy != "" && !core.EqualNames(dns.Fqdn(string(msg.DeliveredBy)), dns.Fqdn(sender))) {
		return refuse(fmt.Sprintf("%s is not this combiner's agent", sender))
	}
	if !core.EqualNames(dns.Fqdn(h.Zone), zone) {
		return refuse(fmt.Sprintf("it names zone %s", h.Zone))
	}
	mpzd, ok := Zones.Get(zone)
	if !ok || !mpzd.Options[tdns.OptMultiProvider] {
		return refuse("the zone is not a multi-provider zone here")
	}
	store := actingHeld.Load()
	if store == nil {
		return refuse("this combiner keeps no hand-overs")
	}
	prev, changed, err := store.take(h, sender)
	switch {
	case errors.Is(err, errHandoverOlder):
		return refuse(fmt.Sprintf("%s is older than the one held: acting by %s", h, prev))
	case err != nil:
		return refuse(err.Error())
	}
	if changed {
		lgCombiner.Info("acting by the serial the agent handed", "zone", zone, "serial", h.Serial, "step", h.Step, "before", prev.String())
		var pubkeyBefore bool
		if prev != nil {
			pubkeyBefore = prev.Sets.Pubkey
		}
		mpzd.actByHandover(conf.MpConfig(), pubkeyBefore)
	}
	if h.Refresh {
		conf.refreshFromUpstream(mpzd)
	}
	resp.Status, resp.Message = "ok", "acting by "+h.String()
	return resp
}

// actByHandover has the combiner act by what it now holds for the zone: its
// multi-provider data and edit rights, the merge of the stored
// contributions, which judges every origin by the sets handed (design
// 3.5), and the zone's content. Not before the zone's first load, which
// reads what is held.
func (mpzd *MPZoneData) actByHandover(mp *MultiProviderConf, pubkeyBefore bool) {
	if !mpzd.Ready {
		return
	}
	apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	signing, ok := actingHeld.Load().signingSet(mpzd.ZoneName, apex)
	if !ok {
		signing = nextSigningSetOf(mpzd.instructions(), mpzd.signingSet())
	}
	// Computed on a wrapper of the zone as served, with a map of its own:
	// the zone's options map is read without a lock.
	mpzd.Lock()
	mpzd.EnsureMP()
	opts := make(map[tdns.ZoneOption]bool, len(mpzd.MPOptions))
	for o, on := range mpzd.MPOptions {
		opts[o] = on
	}
	w := &MPZoneData{ZoneData: mpzd.ZoneData, MP: &MPState{MPdata: mpzd.MP.MPdata}, MPOptions: opts}
	mpzd.Unlock()
	w.populateMPdata(mp, signing)
	if w.MP.MPdata == nil {
		w.MPOptions[tdns.OptAllowEdits] = false
	}
	mpzd.Lock()
	mpzd.MP.MPdata, mpzd.MPOptions = w.MP.MPdata, w.MPOptions
	mpzd.RebuildCombinerData()
	allow := mpzd.MPOptions[tdns.OptAllowEdits]
	mpzd.Unlock()
	if allow {
		if _, err := mpzd.CombineWithLocalChanges(); err != nil {
			lgCombiner.Error("combining by the hand-over failed", "zone", mpzd.ZoneName, "err", err)
		}
	}
	if mpzd.hasPubkey() != pubkeyBefore {
		if err := mpzd.withdrawZoneSignalKeysWithoutConsent(NewHsyncDB(mpzd.KeyDB)); err != nil {
			lgCombiner.Error("failed to load publish instructions; the zone's at-ns publication is not checked against the customer's consent", "zone", mpzd.ZoneName, "err", err)
		}
	}
}

// handedOrigin: by the sets the combiner was handed (design 3.5), the zone
// may carry origin's contribution of rrtype: a DNSKEY from a provider in
// KeySigners, a CDS from one in DSSigners, the origin matched by the
// identity the set names (S3). Every other type passes.
func handedOrigin(r Roles, origin string, rrtype uint16) bool {
	var set []Provider
	switch rrtype {
	case dns.TypeDNSKEY:
		set = r.KeySigners
	case dns.TypeCDS:
		set = r.DSSigners
	default:
		return true
	}
	return slices.ContainsFunc(set, func(p Provider) bool {
		return p.Identity != "" && core.EqualNames(p.Identity, dns.Fqdn(origin))
	})
}

// refreshFromUpstream asks for a refresh of the zone from the combiner's
// upstream (the hand-over's Refresh: the fetch down the provider's chain,
// design 3.1). One already asked for is enough.
func (conf *Config) refreshFromUpstream(mpzd *MPZoneData) {
	zr := tdns.ZoneRefresher{Name: mpzd.ZoneName, ZoneType: mpzd.ZoneType, ZoneStore: mpzd.ZoneStore}
	select {
	case conf.Config.Internal.RefreshZoneCh <- zr:
		lgCombiner.Info("refreshing the zone from upstream, as the agent asks", "zone", mpzd.ZoneName)
	default:
		lgCombiner.Warn("the refresh engine's queue is full; the agent asks again", "zone", mpzd.ZoneName)
	}
}

// waitsForHandover: the combiner holds no hand-over for the zone, and the
// zone's copy carries a serial. Its agent hands it one at the combiner's
// start report; meanwhile the combiner serves what it served (rule 5).
func (mpzd *MPZoneData) waitsForHandover() bool {
	if _, held := actingHeld.Load().get(mpzd.ZoneName); held {
		return false
	}
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		return false
	}
	in, err := ReadInstructions(apex)
	return err == nil && in != nil && in.Serial != 0
}

// combinerActingLine is what the combiner acts by for the zone, as `zone
// mplist` shows it on a combiner; "" on every other role.
func combinerActingLine(mpzd *MPZoneData) string {
	s := actingHeld.Load()
	if s == nil || mpzd == nil || GetProviderZoneRRtypes(mpzd.ZoneName) != nil {
		return ""
	}
	if held, ok := s.get(mpzd.ZoneName); ok {
		apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
		if _, acts := s.actsBy(mpzd.ZoneName, apex); !acts {
			return fmt.Sprintf("by its own copy, serial %d, newer than the %s its agent handed at %s", readingOf(apex).Serial, held.handover, held.since.Format(time.TimeOnly))
		}
		return fmt.Sprintf("acting by %s, handed by its agent at %s", held.handover, held.since.Format(time.TimeOnly))
	}
	if !mpzd.waitsForHandover() {
		return "provisional, by its own copy"
	}
	mpzd.Lock()
	restored := mpzd.MP != nil && len(mpzd.MP.AgentContributions) > 0
	mpzd.Unlock()
	if restored {
		return "waiting for its agent's hand-over, serving what it served"
	}
	return "waiting for its agent's hand-over, serving the copy as it comes"
}

// reportCombinerStart is the combiner's start report: a STATUS-UPDATE
// "combiner-start" to its agent once its router is up, on which the agent
// hands every zone over. It is also rule 5's request for a zone whose copy
// carries a serial and that it holds nothing for (waitsForHandover): sent
// again every minute while such a zone waits, since the agent may not have
// been up. It names no zone of its own (".").
func (conf *Config) reportCombinerStart(ctx context.Context, tm *MPTransportBridge) {
	mp := conf.MpConfig()
	if tm == nil || mp == nil {
		return
	}
	report := func() {
		for _, a := range mp.Agents {
			if a != nil && a.Identity != "" {
				sendDelegationStatusUpdate(tm, dns.Fqdn(a.Identity), ".", "combiner-start", nil, nil)
			}
		}
	}
	report()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if conf.anyZoneWaitsForHandover() {
				report()
			}
		}
	}
}

func (conf *Config) anyZoneWaitsForHandover() bool {
	for _, zone := range conf.InternalMp.MPZoneNames {
		if mpzd, ok := Zones.Get(zone); ok && mpzd.Ready && mpzd.waitsForHandover() {
			return true
		}
	}
	return false
}
