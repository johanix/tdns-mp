/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A signing role learned while the signer runs (plan S18b, on tdns's P5). A
 * signer may not know at a zone's first load what the zone is to it: its copy
 * may be a serial its agent refused (design 3.1, #357), so it takes no role
 * from it. So the zone is withheld at its first load (MPPreRefresh): not Ready,
 * with no policy and no keys, and its refreshes go on. What ends that is its
 * agent's hand-over, which the signer brings about here, at the zone's turn, and
 * again on a tick, since each of these can fail or be told to wait:
 *
 *   - no role: the zone relays its copy (ReleaseWithheld).
 *   - in KeySigners and not Signing: the policy is bound with no signing, also
 *     after a restart, since no first load binds it, and the zone relays its
 *     copy while the key machine runs (BindPolicyWithoutSigning).
 *   - in Signing: the zone signs (StartSigning, which ends both of the others). Its
 *     first keys are tdns's, as at a first load, active at once; a zone its key
 *     machine already runs has them from the machine (T2a), and a start waits for
 *     them. Nothing that validates sees them yet: the leader's steps hold back the
 *     provider's DS and NS records (reconcile_add.go).
 *
 * An agent takes the zone from its own signer, so one with no copy has nothing
 * to read instructions from and can hand its signer nothing, for as long as its
 * signer withholds the zone. It says so, and the signer acts by its own copy,
 * as its first load would otherwise have (signerAgentHasNoCopy).
 */
package tdnsmp

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// signerRoleEvery is how often the signer looks again at every zone's role.
const signerRoleEvery = 30 * time.Second

// The P5 calls the turn makes; a test stands in for them.
var (
	startSigning       = func(ctx context.Context, zd *tdns.ZoneData) error { return zd.StartSigning(ctx, 0) }
	bindWithoutSigning = func(zd *tdns.ZoneData) error { return zd.BindPolicyWithoutSigning() }
)

// signerRoleBook is the signer's turns of its zones' roles: the zones asked, the
// failures logged, and the zones whose agent has no copy.
type signerRoleBook struct {
	mu          sync.Mutex
	pending     map[string]bool
	wake        chan struct{}
	said        map[string]string // by zone, folded: the failure last logged
	provisional map[string]*tdns.ZoneData // by zone, folded: its agent has no copy of this ZoneData
}

// wakeLocked is the book's wake channel, made on first use.
func (b *signerRoleBook) wakeLocked() chan struct{} {
	if b.wake == nil {
		b.wake = make(chan struct{}, 1)
	}
	return b.wake
}

// askSignerRole asks the zone's turn, off the caller's goroutine: signing a
// whole zone holds the zone's lock for as long as it takes.
func (conf *Config) askSignerRole(zone string) {
	b := &conf.InternalMp.signerRoles
	b.mu.Lock()
	if b.pending == nil {
		b.pending = map[string]bool{}
	}
	b.pending[zone] = true
	wake := b.wakeLocked()
	b.mu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
}

// runSignerRoles takes the zones' turns, those asked at once and every zone on
// a tick, until ctx ends.
func (conf *Config) runSignerRoles(ctx context.Context) {
	b := &conf.InternalMp.signerRoles
	b.mu.Lock()
	wake := b.wakeLocked()
	b.mu.Unlock()
	ticker := time.NewTicker(signerRoleEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
			b.mu.Lock()
			zones := b.pending
			b.pending = nil
			b.mu.Unlock()
			for zone := range zones {
				conf.signerRoleTurn(ctx, zone)
			}
		case <-ticker.C:
			for _, zone := range conf.mpZoneNames() {
				conf.signerRoleTurn(ctx, zone)
			}
		}
	}
}

// signerRoleTurn brings the zone to the role this signer acts by. Nothing for a
// zone not loaded yet, whose first load reads what is held, nor for one handed
// nothing whose agent has not said it has no copy: that one stays as it is.
func (conf *Config) signerRoleTurn(ctx context.Context, zone string) {
	mpzd, ok := Zones.Get(zone)
	mp := conf.MpConfig()
	if !ok || mpzd == nil || mp == nil || !mpzd.HasPublishedData() {
		return
	}
	var r Roles
	if handed, ok := actingHeld.Load().roles(zone); ok {
		r = handed
	} else if conf.agentHasNoCopy(zone) {
		_, r = signerSets(mpzd, mp)
	} else {
		return
	}
	self := labelOfIdentity(r, ourHsyncIdentities(mp))
	mpzd.Lock()
	multiProvider := mpzd.Options[tdns.OptMultiProvider]
	bound := mpzd.DnssecPolicy != nil
	signs := bound && mpzd.Options[tdns.OptInlineSigning]
	mpzd.Unlock()
	if !multiProvider {
		return
	}
	withheld := mpzd.Withheld()

	named := self != "" && has(r.Signing, self)
	if self != "" && has(r.KeySigners, self) && !bound && !named {
		conf.bindForKeys(mpzd)
	}
	if named && !signs {
		// a key machine that runs the zone makes its keys one at a time, and tdns
		// takes a KSK alone for a CSK: it would sign the zone with that until its
		// next signing
		if o := conf.InternalMp.KeyLifecycleOwner; o != nil && o.taken(zone) && !firstKeysThere(mpzd) {
			return
		}
		switch err := startSigning(ctx, mpzd.ZoneData); {
		case err == nil:
			conf.noRoleFailure(zone)
			lgSigner.Info("the zone serves its own signatures now", "zone", zone)
			conf.handedOtherwiseMeanwhile(mpzd, mp)
			conf.tookRole(zone)
			pushSignerInventory(conf, zone)
		case errors.Is(err, tdns.ErrKeyGenerationDeferred), errors.Is(err, tdns.ErrSigningHeld):
			lgSigner.Debug("the zone does not start signing yet; tried again", "zone", zone, "why", err)
		default:
			conf.roleFailure(zone, "the zone could not start signing; tried again", err)
		}
		return
	}
	mpzd.ReleaseWithheld()
	if withheld {
		pushSignerInventory(conf, zone)
	}
}

// handedOtherwiseMeanwhile: a start takes as long as signing the whole zone, and
// holds no lock of ours, so a hand-over that no longer has this provider sign may
// have been acted by while it ran, before it switched inline-signing on. That
// hand-over stands: it is acted by again.
func (conf *Config) handedOtherwiseMeanwhile(mpzd *MPZoneData, mp *MultiProviderConf) {
	r, handed := actingHeld.Load().roles(mpzd.ZoneName)
	if !handed {
		return
	}
	if self := labelOfIdentity(r, ourHsyncIdentities(mp)); self == "" || !has(r.Signing, self) {
		lgSigner.Info("the zone started signing as a hand-over took that back; acting by the hand-over", "zone", mpzd.ZoneName)
		mpzd.actBySets(conf, r, conf.signerConfirmers(mpzd.ZoneName))
	}
}

// firstKeysThere: tdns would sign with a KSK and a ZSK of this provider's, by the
// same read of its signing keys as a start makes, not the rows: a row just written
// is not in it yet. A KSK alone reads as a ZSK too, as a CSK.
func firstKeysThere(mpzd *MPZoneData) bool {
	if mpzd.KeyDB == nil {
		return false
	}
	dak, err := mpzd.KeyDB.GetDnssecKeys(mpzd.ZoneName, tdns.DnskeyStateActive)
	if err != nil || dak == nil || len(dak.KSKs) == 0 {
		return false
	}
	return slices.ContainsFunc(dak.ZSKs, func(z *tdns.PrivateKeyCache) bool { return z.KeyId != dak.KSKs[0].KeyId })
}

// bindForKeys binds the zone's policy with no signing, so that its key machine runs.
func (conf *Config) bindForKeys(mpzd *MPZoneData) {
	zone := mpzd.ZoneName
	if err := bindWithoutSigning(mpzd.ZoneData); err != nil {
		conf.roleFailure(zone, "the zone's DNSSEC policy could not be bound, so its key machine does not run; tried again", err)
		return
	}
	conf.noRoleFailure(zone)
	conf.tookRole(zone)
}

// tookRole: the key machine may take the zone now, not at its next tick.
func (conf *Config) tookRole(zone string) {
	if e := conf.InternalMp.KeyLifecycle; e != nil {
		e.TakeConfiguredZones()
		e.distributeAtJoining(zone)
	}
}

// roleFailure logs a failure of the zone's role once, until another comes or it
// goes: the turn tries again on every tick.
func (conf *Config) roleFailure(zone, what string, err error) {
	b := &conf.InternalMp.signerRoles
	key := canonicalName(zone)
	b.mu.Lock()
	if b.said == nil {
		b.said = map[string]string{}
	}
	repeat := b.said[key] == err.Error()
	b.said[key] = err.Error()
	b.mu.Unlock()
	if !repeat {
		lgSigner.Error(what, "zone", zone, "err", err)
	}
}

func (conf *Config) noRoleFailure(zone string) {
	b := &conf.InternalMp.signerRoles
	b.mu.Lock()
	delete(b.said, canonicalName(zone))
	b.mu.Unlock()
}

// agentHasNoCopy: the zone's agent said it has no copy of the zone as it is
// loaded now. Its word was of the ZoneData it was given for; a zone removed and
// added again, or replaced, is another, whose copy may be one its agent refused,
// and its agent says so again.
func (conf *Config) agentHasNoCopy(zone string) bool {
	b := &conf.InternalMp.signerRoles
	key := canonicalName(zone)
	b.mu.Lock()
	defer b.mu.Unlock()
	given := b.provisional[key]
	if given == nil {
		return false
	}
	if now, ok := tdns.Zones.Get(zone); !ok || now != given {
		delete(b.provisional, key)
		return false
	}
	return true
}

// signerAgentHasNoCopy is the agent's word that it has no copy of the zone this
// signer withholds, and takes it from this signer: it can hand it nothing until
// it has. The signer acts by its own copy, as a first load does when nothing
// holds it back, so that the chain starts. It is then one that acts by what it
// last acted by until a hand-over comes. Refused copies cannot be told apart
// here, as its agent knows of none: an agent that knows the zone holds a copy,
// and says nothing of the kind.
func (conf *Config) signerAgentHasNoCopy(mpzd *MPZoneData) {
	zone := mpzd.ZoneName
	// before its first publish there is no copy to act by yet: its next report
	// brings the word again
	if _, handed := actingHeld.Load().get(zone); handed || !mpzd.Withheld() || !mpzd.HasPublishedData() || conf.agentHasNoCopy(zone) {
		return
	}
	lgSigner.Info("its agent has no copy of the zone, which it takes from this signer: acting by this signer's own copy until it hands something", "zone", zone)
	b := &conf.InternalMp.signerRoles
	b.mu.Lock()
	if b.provisional == nil {
		b.provisional = map[string]*tdns.ZoneData{}
	}
	b.provisional[canonicalName(zone)] = mpzd.ZoneData
	b.mu.Unlock()
	mpzd.actBySets(conf, mpzd.roles(), conf.signerConfirmers(zone))
	conf.askSignerRole(zone)
}
