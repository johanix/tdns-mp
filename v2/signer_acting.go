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
 * the hand-over through the accessor S10 made (actingHeld), whatever its
 * copy says (from S7). A signer handed nothing acts
 * by its own copy (rule 5): provisional for a copy that carries no serial;
 * for one that does, it waits for its agent, and signs meanwhile by the
 * signing set it last signed by.
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
		conf.signerHold(zone, h.Sets.Hold)
	}
	if err == nil && h.Refresh {
		conf.refreshFromUpstream(mpzd, lgSigner)
	}
	pushSignerInventory(conf, zone)
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
// reads what is held.
func (mpzd *MPZoneData) actBySignerHandover(conf *Config, confirmers []string) {
	if !mpzd.Ready {
		return
	}
	mp := conf.MpConfig()
	signing, ok := actingHeld.Load().signingSet(mpzd.ZoneName)
	if !ok {
		return
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
	mpzd.Lock()
	mpzd.MP.MPdata, mpzd.MPOptions = w.MP.MPdata, w.MPOptions
	mpdata := mpzd.MP.MPdata
	mpzd.Unlock()
	if mpdata != nil && mpzd.signerSwitch(nil, nil, mp) {
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
// apex carries a serial, so it waits for its agent's (rule 5).
func signerWaits(zone string, apex *tdns.OwnerData) bool {
	s := actingHeld.Load()
	if s == nil {
		return false
	}
	if _, held := s.get(zone); held {
		return false
	}
	in := readingOf(apex)
	return in != nil && in.Serial != 0
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
