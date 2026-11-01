/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The key lifecycle engine of the signer: one driver per owned zone, the
 * Wire over the signer's surroundings, the ticks, and the KEYSTATE signals
 * from the agents routed to the drivers. The owner is registered before
 * tdns's MainInit; a zone named in the config is taken once it is loaded
 * with its DNSSEC policy bound, asked at the signer's start and again on
 * every tick (the S3 rollout, zone by zone).
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// signerWire is the Wire of a signer: the peers are reached through the
// agents (the inventory push), the parent through the resolver, the zone
// through tdns.
type signerWire struct {
	conf *Config
	// push sends the inventory to the agents, the keys sent again marked;
	// nil is pushKeystateInventory (a seam for tests)
	push func(conf *Config, zone string, resend []uint16)
}

func (w *signerWire) mpzd(zone string) *MPZoneData {
	mpzd, ok := Zones.Get(dns.Fqdn(zone))
	if !ok {
		return nil
	}
	return mpzd
}

// OtherSigners: the providers other than this one whose confirmations a
// key's distribution expects (KeyConfirmers, plan S11). Nothing when this
// provider does not sign the zone: the machine must not run there
// (IsSigner), and never waits on itself.
func (w *signerWire) OtherSigners(zone string) []string {
	self, r, signs := w.sets(zone)
	if !signs {
		return nil
	}
	return othersIn(r.KeyConfirmers, self)
}

// DSSigners: the providers other than this one whose KSKs have a DS
// (plan S11); nothing when this provider does not sign the zone.
func (w *signerWire) DSSigners(zone string) []string {
	self, r, signs := w.sets(zone)
	if !signs {
		return nil
	}
	return othersIn(r.DSSigners, self)
}

// IsSigner reports whether this provider signs the zone (Signing).
func (w *signerWire) IsSigner(zone string) bool {
	_, _, signs := w.sets(zone)
	return signs
}

// sets are this provider's label in the zone, the zone's sets
// (signerSets), and whether this provider signs it.
func (w *signerWire) sets(zone string) (self string, r Roles, signs bool) {
	mpzd := w.mpzd(zone)
	if mpzd == nil {
		return "", Roles{}, false
	}
	mp := w.conf.MpConfig()
	if mp == nil {
		mp = &MultiProviderConf{}
	}
	self, r = signerSets(mpzd, mp)
	return self, r, self != "" && has(r.Signing, self)
}

// signerSets are the sets the signer acts by for the zone, and this
// provider's label in them (plan S11): the sets its agent handed it and the
// label its identity has there (S3). Waiting for its agent's hand-over
// (signerWaits), the sets it last acted by and the label its identity has
// there: its copy changes none of its roles (rule 5), not even when the copy
// drops this provider. Otherwise the zone's sets (roles), as before the
// hand-over, and the label its identity has in the zone's HSYNC3 records.
// The label is "" when nothing gives one.
func signerSets(mpzd *MPZoneData, mp *MultiProviderConf) (self string, r Roles) {
	ours := ourHsyncIdentities(mp)
	apex, _ := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if handed, ok := actingHeld.Load().roles(mpzd.ZoneName); ok {
		return labelOfIdentity(handed, ours), handed
	}
	// the data a refresh or a hand-over swaps in under the zone's lock
	mpzd.Lock()
	var kept *MPdata
	if mpzd.MP != nil {
		kept = mpzd.MP.MPdata
	}
	mpzd.Unlock()
	if signerWaits(mpzd.ZoneName, apex) && kept.computed() {
		r = kept.Sets
		return labelOfIdentity(r, ours), r
	}
	if _, label, err := mpzd.matchHsyncIdentity(ours); err == nil {
		self = trimDot(label)
	}
	return self, mpzd.roles()
}

// labelOfIdentity is the label the sets give a provider with one of the
// identities; "" when none does.
func labelOfIdentity(r Roles, identities []string) string {
	for _, set := range [][]Provider{r.Signing, r.KeySigners, r.DSSigners, r.KeyConfirmers, r.Servers} {
		for _, p := range set {
			if p.Identity == "" {
				continue
			}
			for _, id := range identities {
				if core.EqualNames(p.Identity, id) {
					return trimDot(p.Label)
				}
			}
		}
	}
	return ""
}

// othersIn are the labels of set other than self, sorted.
func othersIn(set []Provider, self string) []string {
	var out []string
	for _, p := range set {
		if l := trimDot(p.Label); l != self {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// otherSignerLabels: the providers other than this one whose DNSKEYs are
// published and whose foreign rows are kept (KeySigners, plan S11), and
// whether this provider signs the zone at all.
func otherSignerLabels(mpzd *MPZoneData, mp *MultiProviderConf) ([]string, bool) {
	self, r := signerSets(mpzd, mp)
	if self == "" || !has(r.Signing, self) {
		return nil, false
	}
	return othersIn(r.KeySigners, self), true
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

// Distribute and DistributeRemoval: the signer's keys reach the peers
// through its agents, which distribute the DNSKEY RRset and confirm back
// with a KEYSTATE signal per key; a removal is a push without the key.
func (w *signerWire) Distribute(zone string, keyid uint16) {
	// off the driver's lock: the push is network I/O with its own timeouts
	go pushKeystateInventoryToAllAgents(w.conf, dns.Fqdn(zone))
}
func (w *signerWire) DistributeRemoval(zone string, keyid uint16) {
	go pushKeystateInventoryToAllAgents(w.conf, dns.Fqdn(zone))
}

// Resend pushes the inventory with the key marked as sent again: the agent
// distributes it to the peers again whether or not its key set changed. An
// unmarked push of an unchanged inventory distributes nothing (#256).
func (w *signerWire) Resend(zone string, keyid uint16, removal bool) {
	push := w.push
	if push == nil {
		push = pushKeystateInventory
	}
	go push(w.conf, dns.Fqdn(zone), []uint16{keyid})
}

// ParentDS asks the resolver for the zone's DS RRset: the key tags it holds
// and its TTL. The signer starts a resolver when it owns a zone
// (StartMPSigner); the pointer is read only once the resolver has published
// it, and without one, or on a lookup that fails, the answer is unknown,
// which is not "no DS" (table E7, O7).
func (w *signerWire) ParentDS(zone string) (map[uint16]bool, time.Duration, bool) {
	if !w.conf.Config.Internal.ImrReady.Published() {
		return nil, 0, false
	}
	imr := w.conf.Config.Internal.ImrEngine
	if imr == nil {
		return nil, 0, false
	}
	// bounded: it runs under the driver's lock on the signer's tick. The
	// iterative query is asked directly, not through DefaultRRsetFetcher,
	// which turns a NODATA into an error: a parent that serves no DS must
	// reach the driver as a known, empty answer (O2), and only a lookup
	// that fails as unknown (O7).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	qname := dns.Fqdn(zone)
	servers, ok := imr.Cache.ServersFor(qname, dns.TypeDS)
	if !ok {
		return nil, 0, false
	}
	rrset, rcode, _, _, err := imr.IterativeDNSQuery(ctx, qname, dns.TypeDS, servers, false, edns0.PrivacyNone)
	return parentDSFromAnswer(rrset, rcode, err)
}

// parentDSFromAnswer reads the parent's answer for the driver: a NOERROR
// answer with no DS records, or NXDOMAIN, is known and empty; any other
// rcode, or a lookup that failed, is unknown. The TTL is the shortest among
// the DS records.
func parentDSFromAnswer(rrset *core.RRset, rcode int, err error) (map[uint16]bool, time.Duration, bool) {
	if err != nil {
		return nil, 0, false
	}
	served := map[uint16]bool{}
	var ttl time.Duration
	if rrset != nil {
		for _, rr := range rrset.RRs {
			if ds, ok := rr.(*dns.DS); ok {
				served[ds.KeyTag] = true
				if t := time.Duration(ds.Hdr.Ttl) * time.Second; ttl == 0 || t < ttl {
					ttl = t
				}
			}
		}
	}
	if len(served) > 0 {
		return served, ttl, true
	}
	switch rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return served, 0, true
	}
	return nil, 0, false
}

// ParentServesDS is ParentDS asked about one key.
func (w *signerWire) ParentServesDS(zone string, keyid uint16) (bool, bool) {
	served, _, known := w.ParentDS(zone)
	return served[keyid], known
}

func (w *signerWire) Strip(zone string, keyid uint16) error {
	mpzd := w.mpzd(zone)
	if mpzd == nil {
		return fmt.Errorf("zone %s not loaded", zone)
	}
	_, err := mpzd.StripZoneRRSIGs(context.Background(), func(sig *dns.RRSIG) bool { return sig.KeyTag == keyid })
	return err
}

func (w *signerWire) Resign(zone string) {
	sendResignRequest(w.conf.Config.Internal.ResignQ, dns.Fqdn(zone))
}

func (w *signerWire) ServedDnskeyTTL(zone string) time.Duration {
	if mpzd := w.mpzd(zone); mpzd != nil {
		if rrset, err := mpzd.GetRRset(mpzd.ZoneName, dns.TypeDNSKEY); err == nil && rrset != nil && len(rrset.RRs) > 0 {
			return time.Duration(rrset.RRs[0].Header().Ttl) * time.Second
		}
	}
	return tdns.DefaultDnskeyTTL
}

// KeysChanged: a fresh inventory to every agent, on every column change,
// not only a state change (design §4.1, arrow 2).
func (w *signerWire) KeysChanged(zone string) {
	go pushKeystateInventoryToAllAgents(w.conf, dns.Fqdn(zone))
	// and the CDS follows a ds column change the served DNSKEY RRset does
	// not show (arrow 1): tdns's DS engine is woken
	if kdb := w.conf.Config.Internal.KeyDB; kdb != nil {
		if zd, ok := tdns.Zones.Get(dns.Fqdn(zone)); ok && zd != nil {
			kdb.KeysChanged(zd)
		}
	}
}

func (w *signerWire) Report(zone string, keyid uint16, what string) {
	lgSigner.Warn("key lifecycle: needs the operator", "zone", zone, "keyid", keyid, "what", what)
	if mpzd := w.mpzd(zone); mpzd != nil {
		mpzd.SetKeystateError(fmt.Sprintf("key %d: %s", keyid, what))
	}
}

// policyFor is the owner's part of the zone's policy: the algorithms and
// lifetimes from tdns's policy, the waits and standby counts from kasp,
// the resend interval from the multi-provider config.
func policyFor(conf *Config, zd *tdns.ZoneData) LifecyclePolicy {
	pol := LifecyclePolicy{KSKAlgorithm: dns.ED25519, ZSKAlgorithm: dns.ED25519, PropagationDelay: time.Hour, Margin: time.Hour, ResendAfter: 10 * time.Minute}
	// The withdrawal margin (E8: the RRSIGs a retired key made have left the
	// caches) is the owner's, not the clamp's (Q1: the clamp is mechanism).
	// The kasp has no retire-safety field yet; until it does, the margin is
	// the propagation delay, set below with it.
	if zd != nil && zd.DnssecPolicy != nil {
		p := zd.DnssecPolicy
		pol.KSKAlgorithm, pol.ZSKAlgorithm = p.KSKAlgorithm, p.ZSKAlgorithm
		if p.Mode == tdns.DnssecPolicyModeCSK && p.Algorithm != 0 {
			pol.KSKAlgorithm, pol.ZSKAlgorithm = p.Algorithm, p.Algorithm
		}
		if lifetimeSchedules(p.KSK.Lifetime) {
			pol.KSKLifetime = time.Duration(p.KSK.Lifetime) * time.Second
		}
		if lifetimeSchedules(p.ZSK.Lifetime) {
			pol.ZSKLifetime = time.Duration(p.ZSK.Lifetime) * time.Second
		}
		if p.SigValidity.Default > 0 {
			pol.SigLifetime = time.Duration(p.SigValidity.Default) * time.Second
		}
	}
	if conf != nil && conf.Config != nil {
		pol.PropagationDelay = conf.Config.KaspPropagationDelay()
		pol.Margin = pol.PropagationDelay
		// the standby counts: the zone's policy's own standby-zsks and
		// standby-ksks (the owner's fields, Q1), else the global kasp
		// counts, else one ZSK and no KSK (tdns's StandbyKeyCount)
		var bound *tdns.DnssecPolicy
		if zd != nil {
			bound = zd.DnssecPolicy
		}
		if bound != nil {
			pol.StandbyZSK = conf.Config.StandbyKeyCount(bound, false)
			pol.StandbyKSK = conf.Config.StandbyKeyCount(bound, true)
		} else {
			kasp := conf.Config.Dnssec.Kasp
			pol.StandbyZSK, pol.StandbyKSK = 1, 0
			if kasp.StandbyZskCount > 0 {
				pol.StandbyZSK = kasp.StandbyZskCount
			}
			if kasp.StandbyKskCount > 0 {
				pol.StandbyKSK = kasp.StandbyKskCount
			}
		}
		if mp := conf.MpConfig(); mp != nil && mp.KeyLifecycleResend != "" {
			if d, err := time.ParseDuration(mp.KeyLifecycleResend); err == nil && d > 0 {
				pol.ResendAfter = d
			}
		}
	}
	return pol
}

const foreverLifetime = 0xFFFFFFFF

// tdnsForeverFallback is tdns's foreverLifetimeSecs (its api_structs.go,
// 10000 hours), which tdns does not export. It stands in when tdns's parser
// gives no value for the word; a test holds it to what the parser gives.
const tdnsForeverFallback = uint32(10000 * 3600)

// tdnsForeverLifetime is what tdns stores for `lifetime: forever`, asked of
// its parser once, at start.
var tdnsForeverLifetime = tdnsForever(tdns.GenKeyLifetime("forever"))

// tdnsForever takes the parser's answer for the word. An error, or 0, would
// leave tdns's value unknown and make it a schedule again without a sign:
// the fallback is taken then.
func tdnsForever(lt tdns.KeyLifetime, err error) uint32 {
	if err != nil || lt.Lifetime == 0 {
		return tdnsForeverFallback
	}
	return lt.Lifetime
}

// lifetimeSchedules: whether a policy lifetime is a schedule at all. tdns
// stores `lifetime: forever` as a large finite number of seconds
// (foreverLifetimeSecs in its api_structs.go, 10000 hours), and its own
// rollover paths take that value as "never" (lifetimeSchedulesRoll beside
// it). Neither is exported, so the value is asked of tdns's parser: taken as
// a schedule it rolled the keys of a `forever` policy at about 417 days
// (tdns-mp #134).
func lifetimeSchedules(secs uint32) bool {
	return secs != 0 && secs != foreverLifetime && secs != tdnsForeverLifetime
}

// KeyLifecycleEngine runs the drivers of the owned zones.
type KeyLifecycleEngine struct {
	conf    *Config
	owner   *MPKeyLifecycleOwner
	wire    *signerWire
	mu      sync.Mutex
	zones   map[string]*ZoneKeyLifecycle
	waiting map[string]string // configured zones not ready to take, with why (logged once per reason)
	refused map[string]bool   // configured zones that are not multi-provider: never taken
	idle    map[string]bool   // owned zones driverState found this provider does not sign, said once (plan S11; isIdle judges now)
}

func NewKeyLifecycleEngine(conf *Config, owner *MPKeyLifecycleOwner) *KeyLifecycleEngine {
	return &KeyLifecycleEngine{conf: conf, owner: owner, wire: &signerWire{conf: conf}, zones: map[string]*ZoneKeyLifecycle{}}
}

// driver returns the zone's driver, made on first use once the zone is
// loaded with a policy; nil while it is not.
// driver returns the zone's driver, or nil when the zone is not one the
// machine runs. A cached driver is checked again each time: a zone no
// longer owned, or a zone this provider does not sign by what it acts by,
// drops out of the cache; the latter stays owned and idle. A driver that
// could not restore its persisted state is not cached: the next call tries
// again (owned returns whether the zone is owned even then, so a signal
// for it is not handed to tdns's path).
func (e *KeyLifecycleEngine) driver(zone string) *ZoneKeyLifecycle {
	l, _ := e.driverState(zone)
	return l
}

func (e *KeyLifecycleEngine) driverState(zone string) (l *ZoneKeyLifecycle, owned bool) {
	zone = lifecycleZoneName(zone)
	e.mu.Lock()
	defer e.mu.Unlock()
	zd, ok := tdns.Zones.Get(zone)
	// a zone named in key-lifecycle-zones is owned before it is taken
	// (#191), but its driver runs from the take (TakeConfiguredZones)
	if !ok || zd == nil || !e.owner.Owns(zd) || !e.owner.taken(zone) {
		delete(e.zones, zone)
		return nil, false
	}
	if !e.wire.IsSigner(zone) {
		// taken, and this provider does not sign the zone by what it acts
		// by: the machine would mint keys the zone never carries. The zone
		// stays owned and is not run (plan S11): tdns's own machine does
		// not take it either, and nothing is taken and released again at
		// every tick. Said when it starts.
		if !e.idle[zone] {
			lgSigner.Info("the zone stays owned and idle: this provider does not sign it", "zone", zone)
			if e.idle == nil {
				e.idle = map[string]bool{}
			}
			e.idle[zone] = true
		}
		delete(e.zones, zone)
		return nil, true
	}
	delete(e.idle, zone)
	if l := e.zones[zone]; l != nil {
		return l, true
	}
	if zd.DnssecPolicy == nil {
		lgSigner.Error("key lifecycle: the zone has no DNSSEC policy; nothing to run its keys by", "zone", zone)
		return nil, true
	}
	kdb := e.conf.Config.Internal.KeyDB
	if kdb == nil {
		return nil, true
	}
	l = NewZoneKeyLifecycle(zone, kdb, RealClock, policyFor(e.conf, zd), e.wire)
	l.Log = func(msg string, kv ...any) { lgSigner.Info(msg, kv...) }
	if err := l.Ready(); err != nil {
		lgSigner.Error("key lifecycle: the driver cannot run; trying again next time", "zone", zone, "err", err)
		return nil, true
	}
	if err := l.Reload(); err != nil {
		lgSigner.Error("key lifecycle: restoring the distributions in flight failed; trying again next time", "zone", zone, "err", err)
		return nil, true
	}
	e.zones[zone] = l
	return l, true
}

// Signal routes a KEYSTATE signal from an agent to the zone's driver:
// "propagated" is every expected signer's applied confirmation (the agent
// aggregates them), "rejected" one rejection. Reports whether the zone is
// owned, so the caller can keep today's path for one that is not.
func (e *KeyLifecycleEngine) Signal(zone string, keytag uint16, signal, message string, at time.Time) bool {
	l, owned := e.driverState(zone)
	if !owned {
		return false
	}
	if l == nil {
		// owned, but the driver is not running: the signal is claimed
		// (tdns's path must not act on an owned zone) and dropped; the
		// signer's resend timer brings the answer again. A zone this
		// provider does not sign has nothing to apply it to.
		if e.isIdle(zone) {
			lgSigner.Info("key lifecycle: a signal for a zone this provider does not sign; taken, nothing to apply it to", "zone", zone, "keytag", keytag, "signal", signal)
			return true
		}
		lgSigner.Warn("key lifecycle: signal dropped, the zone's driver is not running", "zone", zone, "keytag", keytag, "signal", signal)
		return true
	}
	e.applySignal(l, zone, keytag, signal, message, at)
	return true
}

// isIdle: the zone is owned and taken and not run, since this provider does
// not sign it (driverState), judged now: a zone taken since the last tick
// is idle before driverState first says so.
func (e *KeyLifecycleEngine) isIdle(zone string) bool {
	zone = lifecycleZoneName(zone)
	zd, ok := tdns.Zones.Get(zone)
	return ok && zd != nil && e.owner.Owns(zd) && e.owner.taken(zone) && !e.wire.IsSigner(zone)
}

// applySignal feeds one signal to the zone's driver.
func (e *KeyLifecycleEngine) applySignal(l *ZoneKeyLifecycle, zone string, keytag uint16, signal, message string, at time.Time) {
	// the signal names the kind of distribution it answers: "propagated"
	// a key's, "removed" its removal (the agent of the same release); a
	// rejection says nothing of the kind
	var err error
	key, removal := false, true
	switch signal {
	case "propagated":
		_, _, err = l.ConfirmAllAt(keytag, "applied", "", at, &key)
	case "removed":
		_, _, err = l.ConfirmAllAt(keytag, "applied", "", at, &removal)
	case "rejected":
		_, _, err = l.ConfirmAllAt(keytag, "rejected", message, at, nil)
	default:
		return
	}
	switch {
	case err == nil:
	case errors.Is(err, ErrNoDistribution):
		// the key was distributed by someone else (tdns's own key state
		// worker before the take, another provider) or the answer is a
		// late duplicate: nothing of ours to apply it to, and nothing wrong
		lgSigner.Debug("key lifecycle: signal about a key not distributed here", "zone", zone, "keytag", keytag, "signal", signal, "err", err)
	default:
		lgSigner.Warn("key lifecycle: signal not applied", "zone", zone, "keytag", keytag, "signal", signal, "err", err)
	}
}

// Foreign hands the zone's driver what the other providers said about
// their keys (the agent's KEYSTATE "foreign", tdns-mp #58). Reports
// whether the zone is owned: for one that is not, nobody writes ds on the
// foreign rows, and the word is dropped.
func (e *KeyLifecycleEngine) Foreign(zone string, keys []core.ForeignKeyState) bool {
	l, owned := e.driverState(zone)
	if !owned {
		return false
	}
	if l == nil {
		lgSigner.Warn("key lifecycle: the other providers' key states dropped, the zone's driver is not running; the agent sends them again with the next inventory", "zone", zone)
		return true
	}
	if err := l.SetForeignStates(keys); err != nil {
		lgSigner.Error("key lifecycle: recording the other providers' key states failed", "zone", zone, "err", err)
	}
	return true
}

// Run ticks every owned zone until ctx ends.
func (e *KeyLifecycleEngine) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.TakeConfiguredZones() // a configured zone loaded or bound since
			e.tickOwned()
		}
	}
}

// tickOwned ticks every owned zone.
func (e *KeyLifecycleEngine) tickOwned() {
	for _, zone := range e.owner.Zones() {
		l := e.driver(zone)
		if l == nil {
			continue
		}
		l.SetHold(e.conf.InternalMp.SignerHolds.held(zone))
		if err := l.Tick(); err != nil {
			lgSigner.Error("key lifecycle: tick failed", "zone", zone, "err", err)
		}
	}
}

// TakeConfiguredZones takes the zones the multi-provider config names.
func (e *KeyLifecycleEngine) TakeConfiguredZones() {
	mp := e.conf.MpConfig()
	if mp == nil {
		return
	}
	// A configured zone is taken once it is loaded with its DNSSEC policy
	// bound, which happens after the engines start (the policy binds on
	// the zone's first load); until then it waits, and Run asks again on
	// every tick. A zone that is not multi-provider is refused, said once,
	// and looked at again on every tick: the option may come to it later.
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.waiting == nil {
		e.waiting = map[string]string{}
	}
	for _, z := range mp.KeyLifecycleZones {
		// as tdns keys its zones and as the rollout gate reads the
		// list: "A.EXAMPLE." names a.example.
		zone := lifecycleZoneName(z)
		if e.owner.taken(zone) {
			continue
		}
		zd, ok := tdns.Zones.Get(zone)
		var why string
		switch {
		case !ok || zd == nil:
			why = "not loaded yet"
		case !zd.Options[tdns.OptMultiProvider]:
			if e.refused == nil {
				e.refused = map[string]bool{}
			}
			if !e.refused[zone] {
				e.refused[zone] = true
				lgSigner.Error("key lifecycle: key-lifecycle-zones names a zone that is not multi-provider; tdns keeps its keys", "zone", zone)
			}
			continue
		case zd.DnssecPolicy == nil:
			why = "its DNSSEC policy is not bound yet"
		}
		if why != "" {
			if e.waiting[zone] != why {
				e.waiting[zone] = why
				lgSigner.Info("key lifecycle: key-lifecycle-zones names a zone not ready to take; asking again on every tick", "zone", zone, "why", why)
			}
			continue
		}
		delete(e.waiting, zone)
		delete(e.refused, zone)
		e.owner.Take(zone)
		lgSigner.Info("key lifecycle: zone taken by tdns-mp's state machine", "zone", zone)
	}
}

// --- the replacement commands (design §5, R7) ---------------------------------

// ErrZoneNotRun: the zone's key lifecycle is not run by tdns-mp's state
// machine (not taken, or not a multi-provider zone with a policy); tdns's
// own commands apply to it.
var ErrZoneNotRun = errors.New("the zone's key lifecycle is not run by tdns-mp")

// bindPolicyForOwner binds a policy to an owned zone on the owner's behalf:
// tdns's SetZonePolicyForOwner (the mechanism fields applied by tdns, the
// owner's fields changing with the binding; a change of mode, algorithm or
// DS model refused). A variable so a test can stand in for it.
var bindPolicyForOwner = tdns.SetZonePolicyForOwner

// KeyLifecycleKey is one key row as the operator sees it.
type KeyLifecycleKey struct {
	KeyId       uint16     `json:"keyid"`
	Role        string     `json:"role"`
	Algorithm   uint8      `json:"algorithm"`
	State       string     `json:"state"`
	Pub         bool       `json:"pub"`
	Sign        bool       `json:"sign"`
	DS          *bool      `json:"ds"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	ActiveAt    *time.Time `json:"active_at,omitempty"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
}

// KeyLifecycleStatus is the zone as the operator sees it: the policy the
// machine applies, the other signers, the keys with their columns, the
// foreign rows, the distributions in flight and the rollovers requested.
type KeyLifecycleStatus struct {
	Zone         string               `json:"zone"`
	PolicyName   string               `json:"policy_name"`
	Policy       LifecyclePolicy      `json:"policy"`
	OtherSigners []string             `json:"other_signers"`
	Keys         []KeyLifecycleKey    `json:"keys"`
	Foreign      []KeyLifecycleKey    `json:"foreign,omitempty"`
	InFlight     []DistributionStatus `json:"in_flight,omitempty"`
	Rollovers    []string             `json:"rollovers,omitempty"`
	// Acting is what the signer acts by for the zone: the serial its agent
	// handed, provisional, or waiting for its agent (plan S11).
	Acting string `json:"acting,omitempty"`
	// Idle: the zone is owned and its machine does not run, since this
	// provider does not sign it by what it acts by (plan S11).
	Idle bool `json:"idle,omitempty"`
	// AlgorithmRollovers are the algorithm rollovers under way, by role
	// (table §6 O4): the old algorithm, the policy's, and the step.
	AlgorithmRollovers []AlgRolloverStatus `json:"algorithm_rollovers,omitempty"`
}

// Zones lists the zones tdns-mp's state machine runs.
func (e *KeyLifecycleEngine) Zones() []string { return e.owner.Zones() }

func (e *KeyLifecycleEngine) driverOf(zone string) (*ZoneKeyLifecycle, error) {
	l := e.driver(zone)
	if l == nil {
		return nil, fmt.Errorf("zone %s: %w", dns.Fqdn(zone), ErrZoneNotRun)
	}
	return l, nil
}

// Status is the zone as the operator sees it. A zone owned and idle has
// what the signer acts by and nothing else.
func (e *KeyLifecycleEngine) Status(zone string) (*KeyLifecycleStatus, error) {
	if l, owned := e.driverState(zone); l == nil && owned && e.isIdle(zone) {
		return &KeyLifecycleStatus{Zone: dns.Fqdn(zone), Acting: signerActingLine(zone), Idle: true}, nil
	}
	l, err := e.driverOf(zone)
	if err != nil {
		return nil, err
	}
	zd, _ := tdns.Zones.Get(l.Zone)
	st := &KeyLifecycleStatus{Zone: l.Zone, OtherSigners: l.Wire.OtherSigners(l.Zone), InFlight: l.InFlight(), Rollovers: l.RolloverRequests(), Acting: signerActingLine(l.Zone)}
	if zd != nil {
		st.PolicyName = zd.DnssecPolicyName
	}
	// the algorithm rollovers from the same read of the rows as the keys:
	// a read that fails fails the status, and no rollover under way shows
	// as over
	l.mu.Lock()
	st.Policy = l.Policy
	all, err := l.rows()
	if err == nil {
		st.AlgorithmRollovers = l.algRolloversOf(all)
	}
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for _, keyid := range keytagsOf(all) {
		k := all[keyid]
		cols, err := l.columnsOf(keyid)
		if err != nil {
			return nil, err
		}
		var ds *bool
		if cols.DS.Valid {
			v := cols.DS.Bool
			ds = &v
		}
		st.Keys = append(st.Keys, KeyLifecycleKey{KeyId: keyid, Role: roleOf(k.Flags), Algorithm: k.Algorithm, State: k.State,
			Pub: cols.Pub, Sign: cols.Sign, DS: ds, PublishedAt: k.PublishedAt, ActiveAt: k.ActiveAt, RetiredAt: k.RetiredAt})
	}
	inv, err := tdns.GetKeyInventory(l.KDB, l.Zone)
	if err != nil {
		return nil, err
	}
	for _, it := range inv {
		if it.State == DnskeyStateForeign {
			st.Foreign = append(st.Foreign, KeyLifecycleKey{KeyId: it.KeyTag, Role: roleOf(it.Flags), Algorithm: it.Algorithm, State: it.State, Pub: it.Pub, Sign: it.Sign, DS: it.DS})
		}
	}
	return st, nil
}

func lifecycleRole(role string) (string, error) {
	switch strings.ToUpper(role) {
	case "KSK", "ZSK":
		return strings.ToUpper(role), nil
	}
	return "", fmt.Errorf("role %q: KSK or ZSK", role)
}

// RequestRollover asks for the role's next standby key to be promoted on
// the next tick (tdns-mpcli signer key rollover). It is the emergency
// rollover, which starts under the agent's hold too (design 3.1, plan S6),
// but at a provider that does not sign the zone: one with no role, or one
// the serial being agreed takes away, makes none, since its keys go with
// its removal. Until the signer acts by what its agent hands it (S11), it
// reads that from its own copy, which is never older than its agent's.
func (e *KeyLifecycleEngine) RequestRollover(zone, role string) (string, error) {
	l, err := e.driverOf(zone)
	if err != nil {
		return "", err
	}
	r, err := lifecycleRole(role)
	if err != nil {
		return "", err
	}
	if e.conf.InternalMp.SignerHolds.held(zone) {
		if mpzd, ok := Zones.Get(l.Zone); ok && mpzd.MP != nil && mpzd.MP.MPdata != nil && !mpzd.MP.MPdata.WeAreSigner {
			return "", fmt.Errorf("zone %s: a transition is under way and this provider does not sign the zone; it starts no rollover, its keys go with its removal", l.Zone)
		}
	}
	l.RequestRollover(r)
	return fmt.Sprintf("Zone %s: %s rollover requested; the next standby %s is promoted on the next tick (a standby is minted first if none is ready)", l.Zone, r, r), nil
}

// CancelRollover withdraws a rollover request not yet fired. During an
// algorithm rollover of the role it takes the algorithm back instead, as
// long as nothing of the new algorithm signs yet: the new keys are
// withdrawn on the next tick. Once a key of the new algorithm signs the
// algorithm rollover is past cancelling: it completes, and the way back is
// a change of the algorithm once it has (a rollover through the same
// steps). A rollover request made in that window is still withdrawn, and
// the answer says both; with no request to withdraw the cancel is refused.
func (e *KeyLifecycleEngine) CancelRollover(zone, role string) (string, error) {
	l, err := e.driverOf(zone)
	if err != nil {
		return "", err
	}
	r, err := lifecycleRole(role)
	if err != nil {
		return "", err
	}
	return cancelRollover(l, r)
}

// cancelRollover is CancelRollover on the zone's driver, the role checked.
func cancelRollover(l *ZoneKeyLifecycle, r string) (string, error) {
	rolls, err := l.AlgorithmRollovers()
	if err != nil {
		// whether an algorithm rollover is under way decides what a
		// cancel does: with that unknown, nothing is done
		return "", fmt.Errorf("zone %s: the %s rollover is not cancelled: %w", l.Zone, r, err)
	}
	for _, roll := range rolls {
		if roll.Role != r {
			continue
		}
		from, to, err := l.CancelAlgorithmRollover(r)
		if errors.Is(err, ErrAlgRollSigns) {
			// the old key waits out T10b or T19 for a DS TTL or a signature
			// lifetime, and a rollover requested meanwhile (one that mints
			// its key first takes hours to fire) is the operator's to
			// withdraw: the refusal is the algorithm's, not the request's
			if l.CancelRollover(r) {
				return fmt.Sprintf("Zone %s: %s rollover request cleared; the %s algorithm rollover to %s is not cancelled: a %s of %s already signs, and it completes on its own",
					l.Zone, r, r, dns.AlgorithmToString[to], r, dns.AlgorithmToString[to]), nil
			}
			return "", fmt.Errorf("zone %s: the %s algorithm rollover to %s cannot be cancelled: a %s of %s already signs, and the roll completes on its own; to go back, set the %s algorithm to %s again once it has, which is a rollover through the same steps",
				l.Zone, r, dns.AlgorithmToString[to], r, dns.AlgorithmToString[to], r, dns.AlgorithmToString[roll.From])
		}
		if err != nil {
			return "", err
		}
		l.CancelRollover(r)
		return fmt.Sprintf("Zone %s: the %s algorithm rollover to %s is cancelled; the %s algorithm is %s again, and the keys of %s not yet signing are withdrawn on the next tick",
			l.Zone, r, dns.AlgorithmToString[to], r, dns.AlgorithmToString[from], dns.AlgorithmToString[to]), nil
	}
	l.CancelRollover(r)
	return fmt.Sprintf("Zone %s: %s rollover request cleared", l.Zone, r), nil
}

// lifecycleAlgorithm reads an algorithm name for the owner's policy: one
// tdns's keystore can generate a key of.
func lifecycleAlgorithm(name string) (uint8, error) {
	alg, ok := dns.StringToAlgorithm[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return 0, fmt.Errorf("algorithm %q is not a DNSSEC algorithm name", name)
	}
	switch alg {
	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519, dns.RSASHA256, dns.RSASHA512:
		return alg, nil
	}
	return 0, fmt.Errorf("algorithm %s: the keystore generates ECDSAP256SHA256, ECDSAP384SHA384, ED25519, RSASHA256 and RSASHA512", dns.AlgorithmToString[alg])
}

// SetAlgorithm changes the owner's algorithm for a role of an owned zone
// (tdns-mpcli signer key policy --ksk-algorithm, --zsk-algorithm): an
// algorithm rollover from the next tick (table §6 O4). The bound tdns
// policy is not touched: tdns's policy binding refuses an algorithm
// change on an owned zone, the algorithm being the owner's field (Q1).
func (e *KeyLifecycleEngine) SetAlgorithm(zone, role, algorithm string) (string, error) {
	l, err := e.driverOf(zone)
	if err != nil {
		return "", err
	}
	r, err := lifecycleRole(role)
	if err != nil {
		return "", err
	}
	alg, err := lifecycleAlgorithm(algorithm)
	if err != nil {
		return "", err
	}
	old, err := l.SetAlgorithm(r, alg)
	if err != nil {
		return "", err
	}
	if old == alg {
		return fmt.Sprintf("Zone %s: the %s algorithm is %s already; nothing changes", l.Zone, r, dns.AlgorithmToString[alg]), nil
	}
	return fmt.Sprintf("Zone %s: the %s algorithm is %s (was %s); an algorithm rollover runs from the next tick: a %s of %s is minted, distributed and published, it signs beside the old one once standby (a KSK once the parent has served its DS for the DS TTL), and the old algorithm's keys leave after that. signer key status shows the step; signer key rollover cancel takes the algorithm back while nothing of %s signs",
		l.Zone, r, dns.AlgorithmToString[alg], dns.AlgorithmToString[old], r, dns.AlgorithmToString[alg], dns.AlgorithmToString[alg]), nil
}

// Retry sends a key's distribution (or removal) again, the rejection
// forgotten and the expected set recomputed (T6).
func (e *KeyLifecycleEngine) Retry(zone string, keyid uint16) (string, error) {
	l, err := e.driverOf(zone)
	if err != nil {
		return "", err
	}
	if !l.HasDistribution(keyid) {
		return "", fmt.Errorf("zone %s: key %d has no distribution in flight; nothing to retry", l.Zone, keyid)
	}
	from, _, err := l.Apply(keyid, CmdRetry)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Zone %s: key %d (%s) distributed again to the current signers", l.Zone, keyid, from), nil
}

// Withdraw gives a key up: its removal is distributed (T7, T7', T7”).
func (e *KeyLifecycleEngine) Withdraw(zone string, keyid uint16) (string, error) {
	l, err := e.driverOf(zone)
	if err != nil {
		return "", err
	}
	from, to, err := l.Apply(keyid, CmdWithdraw)
	if err != nil {
		return "", err
	}
	if from == to {
		return "", fmt.Errorf("zone %s: key %d is %s; withdraw applies to a key in %s, %s or %s (an active key is rolled, a retired one leaves on its own)", l.Zone, keyid, from, KeyStateMpdist, KeyStatePublished, KeyStateStandby)
	}
	return fmt.Sprintf("Zone %s: key %d withdrawn (%s to %s)", l.Zone, keyid, from, to), nil
}

// SetPolicy binds a policy to the zone on the owner's behalf and applies
// its owner fields from the next tick on.
func (e *KeyLifecycleEngine) SetPolicy(ctx context.Context, zone, policyName string) (string, error) {
	l, err := e.driverOf(zone)
	if err != nil {
		return "", err
	}
	zd, ok := tdns.Zones.Get(l.Zone)
	if !ok || zd == nil {
		return "", fmt.Errorf("zone %s is not loaded", l.Zone)
	}
	msg, err := bindPolicyForOwner(ctx, zd, l.KDB, policyName)
	if err != nil {
		return "", err
	}
	l.SetPolicy(policyFor(e.conf, zd))
	return msg, nil
}
