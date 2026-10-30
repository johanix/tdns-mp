/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A provider added, or put back (design 5.1, plan S18a). The record is a
 * transition with nothing to carry out: done once the parts hold the serial
 * (S12's last step). A server role is one step, an addition's: held once
 * the provider's own agent confirms that its nameservers serve the zone
 * from its upstream at an SOA serial no lower than the zone's
 * (serving_check.go), the transfer confirmation. Its operator sets the
 * transfer up: the membership plan's decision 6 has no asking half. Its NS
 * reach the zone and the parent last, by its operator (membership rule 7).
 * A provider that a thaw puts in a list it was not in sends what it
 * contributes again, and every agent asks it for its state.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// serverRoleKey prefixes the key of a server role's step, followed by the
// provider's identity.
const serverRoleKey = "server-role "

const (
	// transferRecheck is how often a provider's agent checks its
	// nameservers again while its server role's step waits for them.
	transferRecheck = 30 * time.Second
	// transferCheckTimeout bounds one check.
	transferCheckTimeout = 20 * time.Second
	// transferHelpAfter: past this, counted from the step, the provider's
	// status tells its operator what to point where.
	transferHelpAfter = 5 * time.Minute
)

func init() {
	registerStepRunner(stepRunner{name: "a server role", kind: stepAddition, steps: serverRoleSteps, holds: serverRoleHolds, status: serverRoleStatus})
}

// serverRoleSteps is a step for each provider in V's servers= whose
// identity the sets held do not serve: a provider that enters servers=. The
// step changes no set: the last step gives V's lists.
func serverRoleSteps(p planView) []plannedStep {
	var steps []plannedStep
	for _, s := range rolesFor(p.to, p.to, 0).Servers {
		if s.Identity == "" || slices.ContainsFunc(p.held.Servers, func(h Provider) bool { return core.EqualNames(h.Identity, s.Identity) }) {
			continue
		}
		steps = append(steps, plannedStep{key: serverRoleKey + canonicalName(s.Identity), provider: s.Identity,
			what: fmt.Sprintf("the nameservers of %s serve the zone from its upstream", s.Identity)})
	}
	return steps
}

// serverRoleOf is the provider of a server role's step, by identity: the
// step's own key is the last it has taken.
func serverRoleOf(step InstrStep) (string, bool) {
	if len(step.Taken) == 0 {
		return "", false
	}
	return strings.CutPrefix(step.Taken[len(step.Taken)-1], serverRoleKey)
}

// serverRoleHolds: at the provider's own agent a server role's step is held
// only once the transfer confirmation passes. Every other agent's part of
// it is its parts holding the step's sets.
func serverRoleHolds(conf *Config, zone string, step InstrStep) bool {
	id, ok := serverRoleOf(step)
	if mp := conf.MpConfig(); !ok || mp == nil || !core.EqualNames(id, mp.Identity) {
		return true
	}
	return conf.InternalMp.transfers.confirmed(conf, zone, step)
}

// serverRoleStatus is what a server role's step waits for, at every agent
// while its provider does not hold it: the provider's nameservers, at the
// zone's serial as this agent holds it; and at the provider's own agent,
// once the step has waited transferHelpAfter, what its operator must point
// where.
func serverRoleStatus(conf *Config, zone string, step heldStep, now time.Time) string {
	id, ok := serverRoleOf(step.InstrStep)
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
	line := fmt.Sprintf("waiting for %s's nameservers to serve the zone from its upstream at serial %d or later", id, copySerial(zone))
	if self && now.Sub(step.at) >= transferHelpAfter {
		line += fmt.Sprintf("; its operator must point %s at %s for the zone's transfer",
			strings.Join(mp.Local.Nameservers, ", "), strings.Join(upstreamOf(instructionsFor(ZoneName(zone)), id), " or "))
	}
	return line
}

// toldStepHeld: id's first-hand stamp tells that it holds step.
func (conf *Config) toldStepHeld(zone, id string, step InstrStep) bool {
	var t *stampTable
	if tm := conf.InternalMp.MPTransport; tm != nil {
		t = tm.stamps
	}
	st, ok := t.firstHand(canonicalName(zone))[canonicalName(id)]
	return ok && st.StepHeld && st.Step != nil && st.Step.Number == step.Number && st.Step.Digest == step.Digest
}

// copySerial is the SOA serial of the zone as this agent holds it: the
// serial a newcomer's nameservers serve at the least.
func copySerial(zone string) uint32 {
	if mpzd, ok := Zones.Get(zone); ok && mpzd != nil && mpzd.ZoneData != nil {
		return mpzd.CurrentSerial
	}
	return 0
}

// upstreamOf are the providers whose keys sign the copy that the provider
// id serves, by identity: its record's upstream, or with none named, every
// signer.
func upstreamOf(in *Instructions, id string) []string {
	label, ok := in.labelOf(id)
	if !ok {
		return nil
	}
	if r, _ := in.record(label); r.Upstream != "" {
		if up := in.identityOf(r.Upstream); up != "" {
			return []string{up}
		}
		return nil
	}
	return identities(in.providers(in.Signers))
}

// signerKeys are the DNSKEYs the providers ids publish, as this agent holds
// them: its own provider's from its signer, another's as that provider's
// agent distributed them.
func (conf *Config) signerKeys(zone string, ids []string) []dns.RR {
	self := conf.MpConfig().Identity
	var keys []dns.RR
	for _, id := range ids {
		if core.EqualNames(id, self) {
			if mpzd, ok := Zones.Get(zone); ok && mpzd != nil {
				mpzd.Lock()
				if mpzd.MP != nil {
					keys = append(keys, mpzd.MP.LocalDNSKEYs...)
				}
				mpzd.Unlock()
			}
			continue
		}
		zdr := conf.InternalMp.ZoneDataRepo
		if zdr == nil {
			continue
		}
		ar, ok := zdr.Repo.Get(ZoneName(zone))
		if !ok {
			continue
		}
		for _, agent := range ar.Data.Keys() {
			if !core.EqualNames(string(agent), id) {
				continue
			}
			if nod, ok := ar.Data.Get(agent); ok {
				if rrset, ok := nod.RRtypes.Get(dns.TypeDNSKEY); ok {
					keys = append(keys, rrset.RRs...)
				}
			}
		}
	}
	return keys
}

// transferBook is the agent's transfer confirmations, by zone: the latest
// check of its nameservers for the server role's step it holds.
type transferBook struct {
	mu    sync.Mutex
	zones map[string]*transferCheck // by zone, folded
	// start runs a check; nil: in a goroutine of its own. A test runs it
	// in place.
	start func(check func())
}

type transferCheck struct {
	step    string // the step's key and digest
	ok      bool
	at      time.Time // when the latest check ended
	running bool
}

// stepName names a step for the book: the zone's active serial, the step's
// key and its digest. A later transition that gives the role again, with
// the same sets, is another step.
func (conf *Config) stepName(zone string, step InstrStep) string {
	if len(step.Taken) == 0 {
		return ""
	}
	var serial uint32
	if active, _ := conf.InternalMp.Instructions.activeSerial(zone); active != nil {
		serial = active.Serial
	}
	return fmt.Sprintf("%d %s %s", serial, step.Taken[len(step.Taken)-1], step.Digest)
}

// confirmed is whether this agent's nameservers serve the zone as step
// needs; a check starts when none runs and the latest is older than
// transferRecheck. Once confirmed it stays so for the step.
func (b *transferBook) confirmed(conf *Config, zone string, step InstrStep) bool {
	name := conf.stepName(zone, step)
	b.mu.Lock()
	if b.zones == nil {
		b.zones = map[string]*transferCheck{}
	}
	c := b.zones[canonicalName(zone)]
	if c == nil || c.step != name {
		c = &transferCheck{step: name}
		b.zones[canonicalName(zone)] = c
	}
	kick := !c.ok && !c.running && (c.at.IsZero() || time.Since(c.at) >= transferRecheck)
	if kick {
		c.running = true
	}
	start := b.start
	b.mu.Unlock()
	if kick {
		check := func() { conf.checkTransfer(zone, name) }
		if start == nil {
			go check()
		} else {
			start(check)
		}
	}
	return b.held(zone, name)
}

// held: the latest check for the step named passed.
func (b *transferBook) held(zone, name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.zones[canonicalName(zone)]
	return c != nil && c.step == name && c.ok
}

// checkTransfer checks that this provider's nameservers serve the zone from
// its upstream (servingChainOK): at an SOA serial no lower than the zone's
// as this agent holds it, signed by its upstream's keys. The outcome is
// logged when it changes.
func (conf *Config) checkTransfer(zone, name string) {
	ctx, cancel := context.WithTimeout(context.Background(), transferCheckTimeout)
	defer cancel()
	mp := conf.MpConfig()
	min := copySerial(zone)
	served, err := servingChainOK(ctx, zone, mp.Local.Nameservers, conf.signerKeys(zone, upstreamOf(instructionsFor(ZoneName(zone)), mp.Identity)), min, time.Now())
	b := &conf.InternalMp.transfers
	b.mu.Lock()
	c := b.zones[canonicalName(zone)]
	if c == nil || c.step != name {
		b.mu.Unlock()
		return // the step moved on meanwhile
	}
	first, was := c.at.IsZero(), c.ok
	c.ok, c.at, c.running = err == nil, time.Now(), false
	b.mu.Unlock()
	if !first && was == (err == nil) {
		return
	}
	if err != nil {
		lg.Info("the transfer confirmation for the step", "zone", zone, "provider", mp.Identity, "ok", false, "serial", served, "want", min, "why", err)
		return
	}
	lg.Info("the transfer confirmation for the step", "zone", zone, "provider", mp.Identity, "ok", true, "serial", served)
	// the zone's turn now, not at its next tick: an agent that leads the
	// zone counts its own step held there; every other agent's stamp
	// tells it at its next beat
	conf.askThaw(zone)
}

// --- A provider put back ---

// enteredLists runs, at this agent's activation of the zone's instructions
// to, what follows for the providers they put in servers= or signers=,
// lists they were not in under from (design 5.1): each other one is asked
// for the zone's state (peer-role), and when this agent's own provider is
// one, the data engine sends what it contributes again (putBack).
func (conf *Config) enteredLists(zone string, from, to *Instructions) {
	mp := conf.MpConfig()
	if from == nil || to == nil || mp == nil {
		return
	}
	conf.InternalMp.CatchUp.peersEntered(ZoneName(zone), from, to)
	if !enteredAList(from, to, mp.Identity) {
		return
	}
	msgQs := conf.InternalMp.MsgQs
	if msgQs == nil || msgQs.SynchedDataCmd == nil {
		return
	}
	select {
	case msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "put-back", Zone: ZoneName(zone)}:
	default:
		lgEngine.Warn("the data engine's queue is full; a provider put back sends nothing again, and the agents' requests for its state get it", "zone", zone)
	}
}

// enteredAList: to puts the provider id in servers= or signers=, a list
// from does not have it in.
func enteredAList(from, to *Instructions, id string) bool {
	label, ok := to.labelOf(id)
	if !ok {
		return false
	}
	was, _ := from.labelOf(id)
	return slices.Contains(to.Servers, label) && !slices.Contains(from.Servers, was) ||
		slices.Contains(to.Signers, label) && !slices.Contains(from.Signers, was)
}

// contributedTypes are the types the provider id may contribute under in:
// NS in servers=, DNSKEY and CDS in signers= (design 5.2's lists).
func contributedTypes(in *Instructions, id string) []string {
	label, ok := in.labelOf(id)
	if !ok {
		return nil
	}
	var out []string
	if slices.Contains(in.Servers, label) {
		out = append(out, "NS")
	}
	if slices.Contains(in.Signers, label) {
		out = append(out, "CDS", "DNSKEY")
	}
	return out
}

// putBack sends again what this agent's provider contributes to the zone
// once a thaw has put it in a list it was not in (design 5.1): a complete
// replace of each type it may now contribute, in the catch-up answer's
// form, to every other member of the zone, and but for its DNSKEYs, which
// reach its combiner through its signer, to its combiner. Its NS are those
// its own data holds: after a withdrawal, its operator's to add again. A
// zone whose answer cannot be complete yet sends nothing: an empty replace
// from an agent that has not read its own state would remove what it
// contributes. Every agent asks it for its state (peer-role) in any case.
func (conf *Config) putBack(zdr *ZoneDataRepo, zone ZoneName) {
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return
	}
	self := AgentId(conf.MpConfig().Identity)
	ops, toCombiner, types := conf.putBackOps(zdr, zone)
	if len(ops) == 0 {
		return
	}
	members, _, _ := zoneParticipants(string(zone), instructionsFor(zone))
	distID := transport.GenerateDistributionID()
	for _, id := range members {
		if core.EqualNames(id, string(self)) {
			continue
		}
		if err := tm.EnqueueForSpecificAgent(zone, AgentId(id), &ZoneUpdate{Zone: zone, AgentId: self, Operations: ops}, distID); err != nil {
			lgEngine.Warn("a provider put back could not send what it contributes to a member", "zone", zone, "member", id, "err", err)
		}
	}
	if len(toCombiner) > 0 {
		if _, err := tm.EnqueueForCombiner(zone, &ZoneUpdate{Zone: zone, AgentId: self, Operations: toCombiner}, ""); err != nil {
			lgEngine.Warn("a provider put back could not send what it contributes to its combiner", "zone", zone, "err", err)
		}
	}
	lgEngine.Info("a provider put back sends what it contributes again", "zone", zone, "types", strings.Join(types, ","))
}

// putBackOps are putBack's operations: to the members, and to the
// combiner; none when the provider contributes nothing or its answer
// cannot be complete yet.
func (conf *Config) putBackOps(zdr *ZoneDataRepo, zone ZoneName) (ops, toCombiner []core.RROperation, types []string) {
	self := AgentId(conf.MpConfig().Identity)
	types = contributedTypes(instructionsFor(zone), string(self))
	if len(types) == 0 {
		return nil, nil, nil
	}
	if why := conf.catchUpIncomplete(zdr, zone, self); why != "" {
		lgEngine.Warn("a provider put back cannot send what it contributes yet; the agents' requests for its state get it", "zone", zone, "why", why)
		return nil, nil, nil
	}
	for _, op := range conf.catchUpOperations(zdr, zone, self) {
		if !slices.Contains(types, op.RRtype) {
			continue
		}
		ops = append(ops, op)
		if op.RRtype != "DNSKEY" {
			toCombiner = append(toCombiner, op)
		}
	}
	return ops, toCombiner, types
}
