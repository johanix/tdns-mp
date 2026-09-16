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
func (w *signerWire) OtherSigners(zone string) []string {
	mpzd := w.mpzd(zone)
	if mpzd == nil {
		return nil
	}
	mp := w.conf.MpConfig()
	if mp == nil {
		mp = &MultiProviderConf{}
	}
	return otherSignerLabels(mpzd, mp)
}

func otherSignerLabels(mpzd *MPZoneData, mp *MultiProviderConf) []string {
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		return nil
	}
	rrset, ok := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !ok || len(rrset.RRs) == 0 {
		return nil
	}
	prr, ok := rrset.RRs[0].(*dns.PrivateRR)
	if !ok {
		return nil
	}
	hp, ok := prr.Data.(*core.HSYNCPARAM)
	if !ok {
		return nil
	}
	ourLabel := ""
	if mp != nil {
		if _, label, err := mpzd.matchHsyncIdentity(ourHsyncIdentities(mp)); err == nil {
			ourLabel = label
		}
	}
	var out []string
	for _, s := range hp.GetSigners() {
		if trimDot(s) == trimDot(ourLabel) {
			continue
		}
		out = append(out, trimDot(s))
	}
	return out
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
	pushKeystateInventoryToAllAgents(w.conf, dns.Fqdn(zone))
}
func (w *signerWire) DistributeRemoval(zone string, keyid uint16) {
	pushKeystateInventoryToAllAgents(w.conf, dns.Fqdn(zone))
}

// ParentServesDS asks the resolver for the zone's DS RRset.
func (w *signerWire) ParentServesDS(zone string, keyid uint16) (bool, bool) {
	imr := w.conf.Config.Internal.ImrEngine
	if imr == nil {
		return false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	pushKeystateInventoryToAllAgents(w.conf, dns.Fqdn(zone))
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
		if p.Clamping.Margin > 0 {
			pol.Margin = p.Clamping.Margin
		}
	}
	if conf != nil && conf.Config != nil {
		pol.PropagationDelay = conf.Config.KaspPropagationDelay()
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
	conf  *Config
	owner *MPKeyLifecycleOwner
	wire  *signerWire
	mu    sync.Mutex
	zones map[string]*ZoneKeyLifecycle
}

func NewKeyLifecycleEngine(conf *Config, owner *MPKeyLifecycleOwner) *KeyLifecycleEngine {
	return &KeyLifecycleEngine{conf: conf, owner: owner, wire: &signerWire{conf: conf}, zones: map[string]*ZoneKeyLifecycle{}}
}

// driver returns the zone's driver, made on first use once the zone is
// loaded with a policy; nil while it is not.
func (e *KeyLifecycleEngine) driver(zone string) *ZoneKeyLifecycle {
	zone = dns.Fqdn(zone)
	e.mu.Lock()
	defer e.mu.Unlock()
	if l := e.zones[zone]; l != nil {
		return l
	}
	zd, ok := tdns.Zones.Get(zone)
	if !ok || zd == nil || zd.DnssecPolicy == nil || !e.owner.Owns(zd) {
		return nil
	}
	kdb := e.conf.Config.Internal.KeyDB
	if kdb == nil {
		return nil
	}
	l := NewZoneKeyLifecycle(zone, kdb, RealClock, policyFor(e.conf, zd), e.wire)
	l.Log = func(msg string, kv ...any) { lgSigner.Info(msg, kv...) }
	if err := l.Reload(); err != nil {
		lgSigner.Error("key lifecycle: reload failed", "zone", zone, "err", err)
	}
	e.zones[zone] = l
	return l
}

// Signal routes a KEYSTATE signal from an agent to the zone's driver:
// "propagated" is every expected signer's applied confirmation (the agent
// aggregates them), "rejected" one rejection. Reports whether the zone is
// owned, so the caller can keep today's path for one that is not.
func (e *KeyLifecycleEngine) Signal(zone string, keytag uint16, signal, message string) bool {
	l := e.driver(zone)
	if l == nil {
		return false
	}
	var err error
	switch signal {
	case "propagated":
		for _, p := range l.Wire.OtherSigners(l.Zone) {
			if _, _, err = l.Confirm(keytag, p, "applied", ""); err != nil {
				break
			}
		}
		if len(l.Wire.OtherSigners(l.Zone)) == 0 {
			_, _, err = l.Apply(keytag, EvDistributed)
		}
	case "rejected":
		_, _, err = l.Confirm(keytag, "peers", "rejected", message)
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
	for _, z := range mp.KeyLifecycleZones {
		e.owner.Take(z)
		lgSigner.Info("key lifecycle: zone taken by tdns-mp's state machine", "zone", dns.Fqdn(z))
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
