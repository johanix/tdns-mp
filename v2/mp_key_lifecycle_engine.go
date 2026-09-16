/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The key lifecycle engine of the signer: one driver per owned zone, the
 * Wire over the signer's surroundings, the ticks, and the KEYSTATE signals
 * from the agents routed to the drivers. The owner is registered before
 * tdns's MainInit; the zones named in the config are taken when the signer
 * starts (the S3 rollout, zone by zone).
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// signerWire is the Wire of a signer: the peers are reached through the
// agents (the inventory push), the parent through the resolver, the zone
// through tdns.
type signerWire struct {
	conf *Config
}

func (w *signerWire) mpzd(zone string) *MPZoneData {
	mpzd, ok := Zones.Get(dns.Fqdn(zone))
	if !ok {
		return nil
	}
	return mpzd
}

// OtherSigners: the zone's HSYNCPARAM signers minus this provider's label.
// Nothing when this provider is not one of the signers: the machine must
// not run there (IsSigner), and never waits on itself.
func (w *signerWire) OtherSigners(zone string) []string {
	others, ok := w.signers(zone)
	if !ok {
		return nil
	}
	return others
}

// IsSigner reports whether this provider is one of the zone's signers.
func (w *signerWire) IsSigner(zone string) bool {
	_, ok := w.signers(zone)
	return ok
}

func (w *signerWire) signers(zone string) ([]string, bool) {
	mpzd := w.mpzd(zone)
	if mpzd == nil {
		return nil, false
	}
	mp := w.conf.MpConfig()
	if mp == nil {
		mp = &MultiProviderConf{}
	}
	return otherSignerLabels(mpzd, mp)
}

// otherSignerLabels: the other signers, and whether this provider is a
// signer at all (its HSYNC identity matched, and its label is listed).
func otherSignerLabels(mpzd *MPZoneData, mp *MultiProviderConf) ([]string, bool) {
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		return nil, false
	}
	rrset, ok := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !ok || len(rrset.RRs) == 0 {
		return nil, false
	}
	prr, ok := rrset.RRs[0].(*dns.PrivateRR)
	if !ok {
		return nil, false
	}
	hp, ok := prr.Data.(*core.HSYNCPARAM)
	if !ok {
		return nil, false
	}
	ourLabel := ""
	if mp != nil {
		if _, label, err := mpzd.matchHsyncIdentity(ourHsyncIdentities(mp)); err == nil {
			ourLabel = trimDot(label)
		}
	}
	if ourLabel == "" {
		return nil, false
	}
	var out []string
	listed := false
	for _, s := range hp.GetSigners() {
		if trimDot(s) == ourLabel {
			listed = true
			continue
		}
		out = append(out, trimDot(s))
	}
	if !listed {
		return nil, false
	}
	return out, true
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

// ParentServesDS asks the resolver for the zone's DS RRset.
func (w *signerWire) ParentServesDS(zone string, keyid uint16) (bool, bool) {
	imr := w.conf.Config.Internal.ImrEngine
	if imr == nil {
		return false, false
	}
	// bounded: it runs under the driver's lock on the signer's tick
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rrset, err := imr.DefaultRRsetFetcher(ctx, dns.Fqdn(zone), dns.TypeDS)
	if err != nil {
		return false, false
	}
	if rrset == nil {
		return false, true
	}
	for _, rr := range rrset.RRs {
		if ds, ok := rr.(*dns.DS); ok && ds.KeyTag == keyid {
			return true, true
		}
	}
	return false, true
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
	}
	if conf != nil && conf.Config != nil {
		pol.PropagationDelay = conf.Config.KaspPropagationDelay()
		pol.Margin = pol.PropagationDelay
		kasp := conf.Config.Dnssec.Kasp
		pol.StandbyZSK, pol.StandbyKSK = 1, 0
		if kasp.StandbyZskCount > 0 {
			pol.StandbyZSK = kasp.StandbyZskCount
		}
		if kasp.StandbyKskCount > 0 {
			pol.StandbyKSK = kasp.StandbyKskCount
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

func lifetimeSchedules(secs uint32) bool { return secs != 0 && secs != foreverLifetime }

// KeyLifecycleEngine runs the drivers of the owned zones.
type KeyLifecycleEngine struct {
	conf    *Config
	owner   *MPKeyLifecycleOwner
	wire    *signerWire
	mu      sync.Mutex
	zones   map[string]*ZoneKeyLifecycle
	waiting map[string]string // configured zones not ready to take, with why (logged once per reason)
	refused map[string]bool   // configured zones that are not multi-provider: never taken
}

func NewKeyLifecycleEngine(conf *Config, owner *MPKeyLifecycleOwner) *KeyLifecycleEngine {
	return &KeyLifecycleEngine{conf: conf, owner: owner, wire: &signerWire{conf: conf}, zones: map[string]*ZoneKeyLifecycle{}}
}

// driver returns the zone's driver, made on first use once the zone is
// loaded with a policy; nil while it is not.
// driver returns the zone's driver, or nil when the zone is not one the
// machine runs. A cached driver is checked again each time: a zone
// released, or a zone this provider no longer signs (its HSYNCPARAM
// changed), drops out of the cache, the latter released too. A driver
// that could not restore its persisted state is not cached: the next call
// tries again (owned returns whether the zone is owned even then, so a
// signal for it is not handed to tdns's path).
func (e *KeyLifecycleEngine) driver(zone string) *ZoneKeyLifecycle {
	l, _ := e.driverState(zone)
	return l
}

func (e *KeyLifecycleEngine) driverState(zone string) (l *ZoneKeyLifecycle, owned bool) {
	zone = dns.Fqdn(zone)
	e.mu.Lock()
	defer e.mu.Unlock()
	zd, ok := tdns.Zones.Get(zone)
	if !ok || zd == nil || !e.owner.Owns(zd) {
		delete(e.zones, zone)
		return nil, false
	}
	if !e.wire.IsSigner(zone) {
		// taken but not a signer of the zone (no HSYNC identity of ours
		// among its HSYNCPARAM signers): the machine would mint keys the
		// zone never carries. Released, so nobody's keys go unmanaged:
		// tdns's own machine runs them again.
		lgSigner.Error("key lifecycle: this provider is not one of the zone's signers; the zone is released to tdns's key machine", "zone", zone)
		delete(e.zones, zone)
		e.owner.Release(zone)
		return nil, false
	}
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
		// owned, but the driver is not running yet: the signal is claimed
		// (tdns's path must not act on an owned zone) and dropped; the
		// signer's resend timer brings the answer again
		lgSigner.Warn("key lifecycle: signal dropped, the zone's driver is not running", "zone", zone, "keytag", keytag, "signal", signal)
		return true
	}
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
		return true
	}
	if err != nil {
		lgSigner.Warn("key lifecycle: signal not applied", "zone", zone, "keytag", keytag, "signal", signal, "err", err)
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
			for _, zone := range e.owner.Zones() {
				l := e.driver(zone)
				if l == nil {
					continue
				}
				if err := l.Tick(); err != nil {
					lgSigner.Error("key lifecycle: tick failed", "zone", zone, "err", err)
				}
			}
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
	// every tick. A zone that is not multi-provider is refused for good.
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.waiting == nil {
		e.waiting = map[string]string{}
	}
	for _, z := range mp.KeyLifecycleZones {
		zone := dns.Fqdn(z)
		if e.owner.taken(zone) || e.refused[zone] {
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
			e.refused[zone] = true
			lgSigner.Error("key lifecycle: key-lifecycle-zones names a zone that is not multi-provider; tdns keeps its keys", "zone", zone)
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

// Status is the zone as the operator sees it.
func (e *KeyLifecycleEngine) Status(zone string) (*KeyLifecycleStatus, error) {
	l, err := e.driverOf(zone)
	if err != nil {
		return nil, err
	}
	zd, _ := tdns.Zones.Get(l.Zone)
	st := &KeyLifecycleStatus{Zone: l.Zone, OtherSigners: l.Wire.OtherSigners(l.Zone), InFlight: l.InFlight(), Rollovers: l.RolloverRequests()}
	if zd != nil {
		st.PolicyName = zd.DnssecPolicyName
	}
	l.mu.Lock()
	st.Policy = l.Policy
	all, err := l.rows()
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
// the next tick (tdns-mpcli signer key rollover).
func (e *KeyLifecycleEngine) RequestRollover(zone, role string) (string, error) {
	l, err := e.driverOf(zone)
	if err != nil {
		return "", err
	}
	r, err := lifecycleRole(role)
	if err != nil {
		return "", err
	}
	l.RequestRollover(r)
	return fmt.Sprintf("Zone %s: %s rollover requested; the next standby %s is promoted on the next tick (a standby is minted first if none is ready)", l.Zone, r, r), nil
}

// CancelRollover withdraws a rollover request not yet fired.
func (e *KeyLifecycleEngine) CancelRollover(zone, role string) (string, error) {
	l, err := e.driverOf(zone)
	if err != nil {
		return "", err
	}
	r, err := lifecycleRole(role)
	if err != nil {
		return "", err
	}
	l.CancelRollover(r)
	return fmt.Sprintf("Zone %s: %s rollover request cleared", l.Zone, r), nil
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
