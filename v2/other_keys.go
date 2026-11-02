/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The other keys (design 5.6, plan S21). An upstream is one step, a role
 * change's, that changes no set: held once the downstream provider's own
 * agent confirms that its nameservers serve the zone from the new upstream
 * at an SOA serial no lower than the one they served (S18a's check). Its
 * operator moves the transfer, and its status says what to point where.
 *
 * pubkey and pubcds are a step each, which changes the flag in the step's
 * sets. Every agent hands the sets to its combiner, which acts by them: it
 * withdraws the KEY from the _signal names at once (combinerTakeHandover),
 * and publishes and withdraws the CDS and CDNSKEY (combiner_signal_cds.go).
 * The KEY goes as it does at the leader's set-up: the leader sends it with
 * its publish instruction, and every agent passes that to its combiner
 * (#206). The provider's nameservers no longer act on their own copy (P6).
 */
package tdnsmp

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
)

const (
	// upstreamKey prefixes the key of an upstream's step, followed by the
	// downstream provider's identity.
	upstreamKey = "upstream "
	// pubkeyStepKey and pubcdsStepKey are the keys of the flags' steps.
	pubkeyStepKey = "signal pubkey"
	pubcdsStepKey = "signal pubcds"
)

func init() {
	registerStepRunner(stepRunner{name: "an upstream", kind: stepRoleChange, steps: upstreamSteps, holds: upstreamHolds, status: upstreamStatus})
	registerStepRunner(stepRunner{name: "pubkey and pubcds", kind: stepRoleChange, steps: signalSteps})
}

// upstreamSteps is a step for each provider whose record names another
// upstream under V, and whose servers serve under the sets held and under V.
// A provider that enters servers= has its server role's step, which checks
// the upstream V names. A signer's servers serve its own signer's copy, so
// it has none. With no from, nothing says what moved.
func upstreamSteps(p planView) []plannedStep {
	if p.from == nil {
		return nil
	}
	var steps []plannedStep
	for _, t := range p.to.Records {
		f, ok := p.from.record(t.Label)
		if !ok || !core.EqualNames(f.Identity, t.Identity) || f.Upstream == t.Upstream {
			continue
		}
		if !slices.Contains(p.to.Servers, t.Label) || slices.Contains(p.to.Signers, t.Label) {
			continue
		}
		if !slices.ContainsFunc(p.held.Servers, func(h Provider) bool { return core.EqualNames(h.Identity, t.Identity) }) {
			continue
		}
		steps = append(steps, plannedStep{key: upstreamKey + canonicalName(t.Identity), provider: t.Identity,
			what: fmt.Sprintf("the nameservers of %s serve the zone from its new upstream", t.Identity)})
	}
	return steps
}

// upstreamMoveOf is the provider of an upstream's step, by identity: the
// step's own key is the last it has taken.
func upstreamMoveOf(step InstrStep) (string, bool) {
	if len(step.Taken) == 0 {
		return "", false
	}
	return strings.CutPrefix(step.Taken[len(step.Taken)-1], upstreamKey)
}

// upstreamHolds: at the provider's own agent an upstream's step is held only
// once its nameservers serve the zone from the new upstream, at the serial
// they served or later. Every other agent's part of it is its parts holding
// the step's sets.
func upstreamHolds(conf *Config, zone string, step InstrStep) bool {
	id, ok := upstreamMoveOf(step)
	mp := conf.MpConfig()
	if !ok || mp == nil || !core.EqualNames(id, mp.Identity) {
		return true
	}
	name := conf.stepName(zone, step)
	b := &conf.InternalMp.transfers
	return b.confirmed(conf, zone, step, func(ctx context.Context) (uint32, error) {
		return b.servedAtFirstCheck(ctx, zone, name, mp.Local.Nameservers)
	})
}

// servedAtFirstCheck is the serial this agent's nameservers served at the
// step's first check whose every nameserver answered, kept for the step. In
// memory: after a restart the serving check asks them again, and a server
// that has moved meanwhile passes on its upstream's signatures.
func (b *transferBook) servedAtFirstCheck(ctx context.Context, zone, name string, nameservers []string) (uint32, error) {
	b.mu.Lock()
	if c := b.zones[canonicalName(zone)]; c != nil && c.step == name && c.served != nil {
		defer b.mu.Unlock()
		return *c.served, nil
	}
	b.mu.Unlock()
	served, err := highestServedSerial(ctx, zone, nameservers)
	if err != nil {
		return 0, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if c := b.zones[canonicalName(zone)]; c != nil && c.step == name {
		c.served = &served
	}
	return served, nil
}

// upstreamStatus is what an upstream's step waits for, at every agent while
// its provider does not hold it; and at the provider's own agent, what its
// operator must point where.
func upstreamStatus(conf *Config, zone string, step heldStep, _ time.Time) string {
	id, ok := upstreamMoveOf(step.InstrStep)
	mp := conf.MpConfig()
	if !ok || mp == nil {
		return ""
	}
	self := core.EqualNames(id, mp.Identity)
	switch {
	case self && conf.InternalMp.transfers.held(zone, conf.stepName(zone, step.InstrStep)):
		return ""
	case !self && conf.toldStepHeld(zone, id, step.InstrStep):
		return ""
	}
	line := fmt.Sprintf("waiting for %s's nameservers to serve the zone from its new upstream", id)
	if self {
		line += operatorMustPoint(mp, zone, id)
	}
	return line
}

// signalSteps is a step for each of pubkey and pubcds that V says otherwise
// than the sets held. Each changes its flag in the sets, and every agent's
// combiner acts by it.
func signalSteps(p planView) []plannedStep {
	to := p.to
	var steps []plannedStep
	if p.held.Pubkey != to.Pubkey {
		st := plannedStep{key: pubkeyStepKey, what: "the zone's KEY at the _signal names " + publishedOrWithdrawn(to.Pubkey),
			sets: func(h Roles) Roles { h.Pubkey = to.Pubkey; return h }}
		if to.Pubkey {
			st.start = (*Config).sendKeyForSignalNames
		}
		steps = append(steps, st)
	}
	if p.held.Pubcds != to.Pubcds {
		steps = append(steps, plannedStep{key: pubcdsStepKey, what: "the zone's CDS at the _signal names " + publishedOrWithdrawn(to.Pubcds),
			sets: func(h Roles) Roles { h.Pubcds = to.Pubcds; return h }})
	}
	return steps
}

func publishedOrWithdrawn(on bool) string {
	if on {
		return "published"
	}
	return "withdrawn"
}

// sendKeyForSignalNames is the leader's own action at the step that gives
// pubkey: the zone's KEY goes again, now with at-ns, to its combiner and the
// zone's other agents. During a roll that is the new key from when its KEY
// was sent, whatever the leader's copy still serves (readZoneKey), and it goes
// under a distribution of its own: the roll waits for the one it booked. A key
// not published yet goes with its take-up when the transition is done, or with
// the roll's own send, by the same sets.
func (conf *Config) sendKeyForSignalNames(zone string) {
	z := ZoneName(zone)
	kdb := conf.zoneKeyDB(z)
	if kdb == nil || conf.InternalMp.MPTransport == nil {
		return
	}
	zk, err := readZoneKey(kdb, z)
	if err != nil {
		lgAgent.Error("the zone's KEY could not be read for the _signal names", "zone", zone, "err", err)
		return
	}
	if zk.held == nil || zk.held.key == nil || (!zk.rolling && (len(zk.published) != 1 || !sameKey(zk.published[0], zk.held.key))) {
		lgAgent.Info("the zone's KEY is not published yet: it goes to the _signal names when it is", "zone", zone)
		return
	}
	if _, _, _, err := sendZoneKEY(conf.InternalMp.MPTransport, z, zk.held.key, ""); err != nil {
		lgAgent.Error("the zone's KEY could not be sent for the _signal names", "zone", zone, "err", err)
	}
}
