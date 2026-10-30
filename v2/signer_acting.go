/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The signer's side of the hand-over (plan S11; acting_handover.go is the
 * agent's, combiner_acting.go the combiner's): the agent hands its signer
 * the same object it hands its combiner, on a KEYSTATE signal "acting".
 * The signer keeps it in its KeyDB (MPActingSerial, read before the zones'
 * first load) and acts by it at once: its multi-provider data, the
 * inline-signing switch and multi-signer mode, the foreign DNSKEY rows by
 * KeySigners, and for a zone its key machine runs, the expected
 * confirmations by KeyConfirmers and the foreign rows' ds by DSSigners.
 * Then its inventory says what it holds. Every reader at the signer reads
 * the hand-over through the accessor S10 made (actingHeld), unless the
 * signer's copy is newer (actsBy, until S7). A signer handed nothing acts
 * by its own copy (rule 5): provisional for a copy with no reading (no
 * serial=, #308), which starts no multi-provider work; for one that reads,
 * it waits for its agent, and signs meanwhile by the signing set it last
 * signed by.
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// pushSignerInventory sends the zone's inventory to the signer's agents
// after a hand-over and for the start report; a seam for the tests.
var pushSignerInventory = pushKeystateInventoryToAllAgents

// signerTakeHandover is the signer's side of a hand-over (KEYSTATE
// "acting"): taken only from an agent of its agents: list. One whose
// records do not give its digest, or older than the one held, is refused.
// Taken, it is kept before it is acted by, and acted by at once, not at the
// next refresh; its hold (S6) is kept whether or not the key machine runs
// here, and whatever the signer acts by. Either way the signer's inventory
// then says what it holds, which is how its agent learns it (the KEYSTATE's
// own confirmation says only that it arrived).
func (conf *Config) signerTakeHandover(sig *KeystateSignalMsg) {
	h := sig.Acting
	zone := dns.Fqdn(sig.Zone)
	refuse := func(why string) {
		if !warnRefusal(zone, why, time.Now()) {
			lgSigner.Debug("refusing a hand-over again", "zone", zone, "sender", sig.SenderID, "reason", why)
			return
		}
		lgSigner.Warn("refusing a hand-over", "zone", zone, "sender", sig.SenderID, "reason", why)
	}
	mp := conf.MpConfig()
	agents := map[string]bool{}
	if mp != nil {
		for _, a := range mp.Agents {
			if a != nil && a.Identity != "" {
				agents[a.Identity] = true
			}
		}
	}
	if !ownAgent(agents, sig.SenderID) {
		refuse(fmt.Sprintf("%s is not this signer's agent", sig.SenderID))
		return
	}
	if !core.EqualNames(dns.Fqdn(h.Zone), zone) {
		refuse(fmt.Sprintf("it names zone %s", h.Zone))
		return
	}
	mpzd, ok := Zones.Get(zone)
	if !ok || !mpzd.Options[tdns.OptMultiProvider] {
		refuse("the zone is not a multi-provider zone here")
		return
	}
	store := actingHeld.Load()
	if store == nil {
		refuse("this signer keeps no hand-overs")
		return
	}
	confirmers := conf.signerConfirmers(zone)
	prev, changed, err := store.take(h, sig.SenderID)
	switch {
	case errors.Is(err, errHandoverOlder):
		refuse(fmt.Sprintf("%s is older than the one held: acting by %s", h, prev))
	case err != nil:
		refuse(err.Error())
	case changed:
		lgSigner.Info("acting by the serial the agent handed", "zone", zone, "serial", h.Serial, "step", h.Step, "before", prev.String())
		mpzd.actBySignerHandover(conf, confirmers)
	}
	if err == nil {
		refusalLogged.Delete(handoverKey(zone))
		conf.signerHold(zone, h.Sets.Hold)
	}
	if err == nil && h.Refresh {
		conf.refreshFromUpstream(mpzd, lgSigner)
	}
	pushSignerInventory(conf, zone)
}

// refusalLogged is the refusal last logged for each zone, and when: the
// agent hands a zone the signer refuses again every signerHandoverResend,
// and the same refusal is logged once per handoverResend, at Debug
// between. A hand-over taken clears it.
var refusalLogged sync.Map // handoverKey(zone) -> refusal

type refusal struct {
	why string
	at  time.Time
}

// warnRefusal: the refusal is not the one last logged for the zone, or
// that was logged handoverResend ago; it is noted as logged now. The notes
// that old are dropped then, since they no longer quiet anything: the zone
// a refused message names is the sender's, and they would pile up.
func warnRefusal(zone, why string, now time.Time) bool {
	key := handoverKey(zone)
	if v, ok := refusalLogged.Load(key); ok {
		if last := v.(refusal); last.why == why && now.Sub(last.at) < handoverResend {
			return false
		}
	}
	refusalLogged.Range(func(k, v any) bool {
		if now.Sub(v.(refusal).at) >= handoverResend {
			refusalLogged.Delete(k)
		}
		return true
	})
	refusalLogged.Store(key, refusal{why: why, at: now})
	return true
}

// signerConfirmers are the providers the zone's key machine expects
// confirmations from (KeyConfirmers), as the signer acts by them now; nil
// for a zone it does not run.
func (conf *Config) signerConfirmers(zone string) []string {
	e := conf.InternalMp.KeyLifecycle
	if e == nil {
		return nil
	}
	return e.wire.OtherSigners(zone)
}

// actBySignerHandover has the signer act by what it now holds for the zone,
// at once (plan S11): its multi-provider data by the sets handed; the
// inline-signing switch and multi-signer mode; the other signers' DNSKEYs
// kept as foreign rows by KeySigners, with a re-sign when that changed what
// is served; and, for a zone its key machine runs, the distributions in
// flight expecting KeyConfirmers when they changed from confirmers, and the
// foreign rows' ds by DSSigners. Not before the zone's first load, which
// reads what is held; nor while its copy is newer than the hand-over
// (actsBy), when the copy is what it acts by.
func (mpzd *MPZoneData) actBySignerHandover(conf *Config, confirmers []string) {
	if !mpzd.Ready {
		return
	}
	mp := conf.MpConfig()
	apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	signing, ok := actingHeld.Load().signingSet(mpzd.ZoneName, apex)
	if !ok {
		return
	}
	// Computed on a wrapper of the zone as served, with a map of its own:
	// the zone's options map is read without a lock. One refresh or
	// hand-over at a time (mpDataLock), through the switch, not the re-sign
	// request.
	mpMu := mpDataLock(mpzd.ZoneName)
	mpMu.Lock()
	mpzd.Lock()
	mpzd.EnsureMP()
	opts := make(map[tdns.ZoneOption]bool, len(mpzd.MPOptions))
	for o, on := range mpzd.MPOptions {
		opts[o] = on
	}
	w := &MPZoneData{ZoneData: mpzd.ZoneData, MP: &MPState{MPdata: mpzd.MP.MPdata}, MPOptions: opts}
	mpzd.Unlock()
	w.populateMPdata(mp, signing)
	mpzd.Lock()
	mpzd.MP.MPdata, mpzd.MPOptions = w.MP.MPdata, w.MPOptions
	mpdata := mpzd.MP.MPdata
	mpzd.Unlock()
	var switched, resign bool
	if mpdata != nil {
		switched, resign = mpzd.signerSwitch(nil, nil, mp)
	}
	mpMu.Unlock()
	// after the lock: the request can wait on a full ResignQ
	if switched || resign {
		sendResignRequest(tdns.Conf.Internal.ResignQ, mpzd.ZoneName)
	}
	if e := conf.InternalMp.KeyLifecycle; e != nil {
		e.handedOver(mpzd.ZoneName, confirmers)
	}
}

// handedOver: a hand-over changed what the signer acts by for the zone.
// For a zone the machine runs, every distribution in flight expects the
// providers it expects now when they changed (SignersChanged), and the
// foreign rows' ds follows DSSigners. While the zone's rollovers pause for
// a provider leaving the signing set (#147) neither moves: a rollover under
// way waits where it is, and the first tick after the pause catches up.
func (e *KeyLifecycleEngine) handedOver(zone string, confirmers []string) {
	l := e.driver(zone)
	if l == nil || len(e.wire.leavers(zone)) > 0 {
		return
	}
	if !slices.Equal(confirmers, e.wire.OtherSigners(zone)) {
		if err := l.SignersChanged(); err != nil {
			lgSigner.Error("key lifecycle: the distributions in flight could not follow the providers handed", "zone", zone, "err", err)
		}
	}
	if err := l.ApplyForeign(); err != nil {
		lgSigner.Error("key lifecycle: the other providers' ds could not follow the providers handed", "zone", zone, "err", err)
	}
}

// signerWaits: the signer holds no hand-over for the zone and the copy at
// apex has a reading, which carries a serial (#308), so it waits for its
// agent's (rule 5).
func signerWaits(zone string, apex *tdns.OwnerData) bool {
	s := actingHeld.Load()
	if s == nil {
		return false
	}
	if _, held := s.get(zone); held {
		return false
	}
	return readingOf(apex) != nil
}

// signerActingLine is what the signer acts by for the zone, for `signer
// key status`; "" on every other role.
func signerActingLine(zone string) string {
	s := actingHeld.Load()
	mpzd, ok := Zones.Get(dns.Fqdn(zone))
	if s == nil || !ok || mpzd == nil {
		return ""
	}
	apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if held, ok := s.get(mpzd.ZoneName); ok {
		h := held.handover
		if _, acts := s.actsBy(mpzd.ZoneName, apex); !acts {
			return fmt.Sprintf("by its own copy, serial %d, newer than the %d its agent handed at %s", readingOf(apex).Serial, h.Serial, held.since.Format(time.TimeOnly))
		}
		line := fmt.Sprintf("acting by %d, handed at %s", h.Serial, held.since.Format(time.TimeOnly))
		if h.Step > 0 {
			line = fmt.Sprintf("acting by %d, step %d, handed at %s", h.Serial, h.Step, held.since.Format(time.TimeOnly))
		}
		return line
	}
	if !signerWaits(mpzd.ZoneName, apex) {
		return "provisional"
	}
	return "waiting for its agent's hand-over"
}

// reportSignerStart is the signer's start report (rule 5's request, plan
// S11): once a zone is loaded here its inventory goes to its agent, which
// says what the signer holds for it, nothing included; and every minute
// after, again for each zone that waits for its agent's hand-over
// (signerWaits), since the agent may not have been up. The agent hands a
// zone over whenever the signer does not hold what it wants.
func (conf *Config) reportSignerStart(ctx context.Context) {
	reported := map[string]bool{}
	report := func() {
		for _, zone := range conf.InternalMp.MPZoneNames {
			mpzd, ok := Zones.Get(zone)
			if !ok || mpzd == nil || !mpzd.Ready {
				continue
			}
			apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
			if reported[mpzd.ZoneName] && !signerWaits(mpzd.ZoneName, apex) {
				continue
			}
			reported[mpzd.ZoneName] = true
			pushSignerInventory(conf, mpzd.ZoneName)
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
			report()
		}
	}
}
