/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A signer added, and a server that becomes a signer (design 5.1, 5.3, plan
 * S18b). The leader's steps, each confirmed by every voting member:
 *
 *  1. Its keys. The joiner enters KeySigners and KeyConfirmers, and once every
 *     member's parts hold that, its signer is handed it too: another signer's
 *     combiner would refuse a key from a provider its sets do not name, and a
 *     rejected key waits for its operator. Its key machine makes its first keys
 *     (which a hold lets it: a role with no active key gets one) and distributes
 *     them; the step waits until its key states show a KSK and a ZSK published,
 *     which needs every other signer to have applied them.
 *  2. Its DS. It enters DSSigners. Its KSK's ds=1 puts its DS in the DS set, the
 *     leader syncs under parentsync=agent, and the step waits until the parent
 *     serves it, whoever put it there.
 *  3. The caches' time. Its key machine waits the DS TTL at the parent before its
 *     KSK goes active (T9), asking one server: the step waits until its key states
 *     show them active, and for the DS TTL from when every server served its DS.
 *     Its agent asks its nameservers what they serve, once it serves at all, for
 *     the serial its signed copy must land above.
 *  4. Its own signatures. It enters Signing. Its signer starts signing, its agent
 *     tells its operator it may switch its servers to its own signer, and it holds
 *     the step once its nameservers serve a DNSKEY RRset signed by its own KSK.
 *
 * The DS and DNSKEY steps wait for an emergency rollover (design 3.3). With no
 * provider signing yet there are no signatures to go with a DS: the zone's first
 * signer signs before its DS goes to the parent.
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// signerAddKey prefixes the key of a signer's step: its part, a space and the
// provider's identity.
const signerAddKey = "signer-add "

// The parts of a signer's addition.
const (
	signerAddAccept = "accept"
	signerAddMint   = "keys"
	signerAddDS     = "ds"
	signerAddCaches = "caches"
	signerAddOwn    = "own"
)

const (
	// signerAddLookEvery is how often the leader looks at what the parent
	// serves while a step waits for it.
	signerAddLookEvery = 15 * time.Second
	// signerAddSyncEvery is how often it asks the sync again meanwhile.
	signerAddSyncEvery = time.Minute
)

func init() {
	registerStepRunner(stepRunner{name: "a signer role", kind: stepAddition, steps: signerAddSteps, holds: signerAddHolds, status: signerAddStatus})
}

// signerAddKeyParts is a step key's part and provider, by identity.
func signerAddKeyParts(key string) (id, part string, ok bool) {
	rest, ok := strings.CutPrefix(key, signerAddKey)
	if !ok {
		return "", "", false
	}
	part, id, ok = strings.Cut(rest, " ")
	return id, part, ok
}

// signerAddOf is the provider and the part of a signer's step: the step's own
// key is the last it has taken.
func signerAddOf(step InstrStep) (id, part string, ok bool) {
	if len(step.Taken) == 0 {
		return "", "", false
	}
	return signerAddKeyParts(step.Taken[len(step.Taken)-1])
}

// addProvider is set with p in it, in a slice of its own.
func addProvider(set []Provider, p Provider) []Provider {
	if slices.ContainsFunc(set, func(o Provider) bool { return core.EqualNames(o.Identity, p.Identity) }) {
		return set
	}
	return append(slices.Clip(set), p)
}

// signerAddSteps are the steps of each provider in V's signers= whose signing
// has not started by the sets held, or whose steps have begun: planned again
// from what is in place, each step once.
func signerAddSteps(p planView) []plannedStep {
	var steps []plannedStep
	first := len(p.held.Signing) == 0
	for _, s := range rolesFor(p.to, p.to, 0).Signing {
		if s.Identity == "" {
			continue
		}
		begun := slices.ContainsFunc(p.taken, func(key string) bool {
			id, _, ok := signerAddKeyParts(key)
			return ok && core.EqualNames(id, s.Identity)
		})
		if !begun && slices.ContainsFunc(p.held.Signing, func(o Provider) bool { return core.EqualNames(o.Identity, s.Identity) }) {
			continue
		}
		steps = append(steps, signerAddStepsOf(s, first)...)
	}
	return steps
}

// signerAddStepsOf are the steps of the provider joiner; first, a provider that
// joins a zone nobody signs yet.
func signerAddStepsOf(joiner Provider, first bool) []plannedStep {
	id := joiner.Identity
	key := func(part string) string { return signerAddKey + part + " " + canonicalName(id) }
	what := func(n int, part string) string { return fmt.Sprintf("adding signer %s: step %d (%s)", id, n, part) }
	accept := plannedStep{key: key(signerAddAccept), provider: id, keys: true, what: what(1, "the other signers take its keys"),
		sets: func(h Roles) Roles {
			h.KeySigners, h.KeyConfirmers = addProvider(h.KeySigners, joiner), addProvider(h.KeyConfirmers, joiner)
			return h
		}}
	mint := plannedStep{key: key(signerAddMint), provider: id, keys: true, what: what(1, "its first keys, published"),
		wait: func(conf *Config, zone string, _ time.Time) string {
			if conf.joinerKeysIn(zone, id, KeyStatePublished, KeyStateStandby, KeyStateActive) {
				return ""
			}
			return id + " (its KSK and ZSK published)"
		}}
	ds := plannedStep{key: key(signerAddDS), provider: id, keys: true, what: what(2, "its DS at the parent"),
		sets: func(h Roles) Roles {
			h.DSSigners = addProvider(h.DSSigners, joiner)
			return h
		},
		wait: func(conf *Config, zone string, _ time.Time) string {
			if conf.joinerDSAtParent(zone, id) {
				return ""
			}
			return "the parent (" + id + "'s DS)"
		}}
	caches := plannedStep{key: key(signerAddCaches), provider: id, what: what(3, "the caches' time"),
		wait: func(conf *Config, zone string, since time.Time) string {
			switch {
			case !conf.joinerKeysIn(zone, id, KeyStateActive):
				return id + " (its KSK and ZSK active)"
			case time.Since(since) < conf.InternalMp.signerAdds.parentDSTTL(conf, zone):
				return "the DS TTL at the parent, since every server there serves " + id + "'s DS"
			}
			return ""
		}}
	own := plannedStep{key: key(signerAddOwn), provider: id, what: what(4, "its own signatures served"),
		sets: func(h Roles) Roles {
			h.Signing = addProvider(h.Signing, joiner)
			return h
		}}
	if first {
		return []plannedStep{accept, mint, caches, own, ds}
	}
	return []plannedStep{accept, mint, ds, caches, own}
}

// forOwnSigner is what this agent hands its signer of h: at its own provider's
// first step, h without itself in KeySigners and KeyConfirmers, since its signer
// would make its first keys at once and some other signer may not hold the step
// yet. It is handed them at the next step, which the leader takes once every
// voting member holds this one.
func (conf *Config) forOwnSigner(zone string, h *ActingHandover) *ActingHandover {
	mp := conf.MpConfig()
	in, ok := conf.InternalMp.Instructions.reconcileInputs(zone)
	if h == nil || mp == nil || !ok || !in.hasStep {
		return h
	}
	id, part, add := signerAddOf(in.step.InstrStep)
	if !add || part != signerAddAccept || !core.EqualNames(id, mp.Identity) {
		return h
	}
	out := func(set []Provider) []Provider {
		return slices.DeleteFunc(slices.Clone(set), func(p Provider) bool { return core.EqualNames(p.Identity, id) })
	}
	c := *h
	c.Sets.KeySigners, c.Sets.KeyConfirmers = out(h.Sets.KeySigners), out(h.Sets.KeyConfirmers)
	return &c
}

// joinerKeysIn: the provider id's key states, as this agent holds them, show a
// KSK and a ZSK each in one of states: its own signer's inventory, or what
// another provider's agent said with its distributions.
func (conf *Config) joinerKeysIn(zone, id string, states ...string) bool {
	var ksk, zsk bool
	note := func(flags uint16, state string) {
		switch {
		case !slices.Contains(states, state):
		case flags&dns.SEP != 0:
			ksk = true
		default:
			zsk = true
		}
	}
	conf.joinerKeys(zone, id, func(flags uint16, _ uint16, state string, _ *bool) { note(flags, state) })
	return ksk && zsk
}

// joinerKeys calls each with what this agent knows of each of id's keys: its
// flags, its key tag, its state and its ds.
func (conf *Config) joinerKeys(zone, id string, each func(flags, keytag uint16, state string, ds *bool)) {
	zone = dns.Fqdn(zone)
	if mp := conf.MpConfig(); mp != nil && core.EqualNames(id, mp.Identity) {
		if mpzd, ok := Zones.Get(zone); ok && mpzd != nil {
			if snap := mpzd.GetLastKeyInventory(); snap != nil {
				for _, it := range snap.Inventory {
					if it.State != DnskeyStateForeign {
						each(it.Flags, it.KeyTag, it.State, it.DS)
					}
				}
			}
		}
		return
	}
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return
	}
	for agent, share := range tm.foreignSharesFor(ZoneName(zone)) {
		if !core.EqualNames(string(agent), id) {
			continue
		}
		for _, st := range share.states {
			if i := slices.IndexFunc(share.dnskeys, func(dk *dns.DNSKEY) bool { return dk.KeyTag() == st.KeyTag }); i >= 0 {
				each(share.dnskeys[i].Flags, st.KeyTag, st.State, st.DS)
			}
		}
	}
}

// joinerDSAtParent: the parent, as last looked at, serves at every server the DS
// of a KSK of id whose ds is set. A look is asked while the step waits, and under
// parentsync=agent the leader's sync asked again now and then: explicit, an
// update only where the parent differs. Under parentsync=owner the owner adds
// the DS, and the step's test is the same.
func (conf *Config) joinerDSAtParent(zone, id string) bool {
	var tags []uint16
	conf.joinerKeys(zone, id, func(flags, keytag uint16, _ string, ds *bool) {
		if flags&dns.SEP != 0 && ds != nil && *ds {
			tags = append(tags, keytag)
		}
	})
	seen, known := conf.InternalMp.signerAdds.parentDS(conf, zone)
	if known && slices.ContainsFunc(tags, func(t uint16) bool { return seen.tags[t] }) {
		return true
	}
	if rolesForZone(ZoneName(zone)).ParentSync == core.HsyncParentSyncAgent && conf.InternalMp.signerAdds.syncDue(conf, zone) {
		// the sync may wait for the zone's key, whose offers now pass
		// (offerHeld): the key rounds look at once
		conf.InternalMp.CatchUp.keyCheck(ZoneName(zone))
		askJoinersDS(conf, zone, fmt.Sprintf("the parent does not serve the DS of %s yet", id))
	}
	return false
}

// askJoinersDS asks the leader's delegation sync; a test stands in for it.
var askJoinersDS = func(conf *Config, zone, why string) { conf.requestDelegationSync(nil, zone, why) }

// joinersDSAsked: the step held is a joiner's DS, and under parentsync=agent the
// leader's sync is what adds it: the step's own, so the zone's key is published
// and offered for it (offerHeld).
func (conf *Config) joinersDSAsked(zone string) bool {
	in, ok := conf.InternalMp.Instructions.reconcileInputs(zone)
	if !ok || !in.hasStep {
		return false
	}
	_, part, add := signerAddOf(in.step.InstrStep)
	return add && part == signerAddDS && rolesForZone(ZoneName(zone)).ParentSync == core.HsyncParentSyncAgent
}

// parentDSSeen is what the parent serves of the zone's DS RRset: the key tags
// that every server that answered holds, and the largest TTL they gave it.
type parentDSSeen struct {
	tags map[uint16]bool
	ttl  time.Duration
}

// parentDSLook asks the parent's servers for the zone's DS RRset. A test stands
// in for it.
var parentDSLook = func(conf *Config, zone string) (parentDSSeen, error) {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil || mpzd.ZoneData == nil {
		return parentDSSeen{}, fmt.Errorf("zone %s is not here", zone)
	}
	if conf.Config == nil || conf.Config.Internal.ImrEngine == nil {
		return parentDSSeen{}, fmt.Errorf("no resolver to ask the parent of %s with yet", zone)
	}
	if err := mpzd.FetchParentData(conf.Config.Internal.ImrEngine); err != nil {
		return parentDSSeen{}, err
	}
	return dsAtEveryServer(mpzd.ParentServers, func(server string) ([]dns.RR, error) {
		return askParentDS(mpzd.ZoneName, server)
	})
}

// askParentDS asks one parent server for the zone's DS RRset. NODATA and NXDOMAIN
// are answers that hold none; any other rcode is no answer. tdns.AuthQuery makes
// an error of NXDOMAIN.
func askParentDS(zone, server string) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeDS)
	m.SetEdns0(dns.DefaultMsgSize, false)
	res, err := dns.Exchange(m, server)
	switch {
	case err != nil:
		return nil, err
	case res.Rcode == dns.RcodeNameError:
		return nil, nil
	case res.Rcode != dns.RcodeSuccess:
		return nil, fmt.Errorf("%s answers %s", server, dns.RcodeToString[res.Rcode])
	}
	return res.Answer, nil
}

// dsAtEveryServer is parentDSSeen from asking each of servers. A validator may
// be handed the DS RRset of any of them, and one without the joiner's DS finds
// nothing to validate its signatures with, so a tag counts only if every server
// that answers holds it. One that does not answer hands nothing to anyone; with
// no answer at all nothing is known.
func dsAtEveryServer(servers []string, ask func(server string) ([]dns.RR, error)) (parentDSSeen, error) {
	var seen parentDSSeen
	var last error
	for _, server := range servers {
		rrs, err := ask(server)
		if err != nil {
			last = err
			continue
		}
		tags := map[uint16]bool{}
		for _, rr := range rrs {
			if ds, ok := rr.(*dns.DS); ok {
				tags[ds.KeyTag] = true
				seen.ttl = max(seen.ttl, time.Duration(ds.Hdr.Ttl)*time.Second)
			}
		}
		if seen.tags != nil {
			maps.DeleteFunc(tags, func(tag uint16, _ bool) bool { return !seen.tags[tag] })
		}
		seen.tags = tags
	}
	if seen.tags != nil {
		return seen, nil
	}
	if last == nil {
		last = errors.New("no parent server is known")
	}
	return parentDSSeen{}, last
}

// --- This provider's part ---

// signerAddHolds: at the provider's own agent, its step 3 is held once it knows
// what its nameservers serve, where it serves, and its step 4 once its signer
// signs and, where its servers are to serve its copy, they serve its signatures.
// Every other agent's part is its parts holding the step's sets.
func signerAddHolds(conf *Config, zone string, step InstrStep) bool {
	id, part, ok := signerAddOf(step)
	mp := conf.MpConfig()
	if !ok || mp == nil || !core.EqualNames(id, mp.Identity) {
		return true
	}
	b := &conf.InternalMp.signerAdds
	switch part {
	case signerAddCaches:
		return !servesUnder(step, id) || b.servedKnown(conf, zone)
	case signerAddOwn:
		if !conf.ownSignerSigns(zone) {
			return false
		}
		if !servesOwnCopy(instructionsFor(ZoneName(zone)), id) {
			return true
		}
		if conf.InternalMp.reconciles.sayOnce(canonicalName(zone), "may switch") {
			lg.Info("the provider may switch its servers to its own signer", "zone", zone, "provider", id)
		}
		return b.ownServed(conf, zone)
	}
	return true
}

// signerAddStatus is what a signer's step waits for that the leader's view does
// not say: at the provider's own agent, its signer and its operator; at any
// other, its nameservers.
func signerAddStatus(conf *Config, zone string, step heldStep, _ time.Time) string {
	id, part, ok := signerAddOf(step.InstrStep)
	mp := conf.MpConfig()
	if !ok || mp == nil || part != signerAddOwn {
		return ""
	}
	if !core.EqualNames(id, mp.Identity) {
		if conf.toldStepHeld(zone, id, step.InstrStep) {
			return ""
		}
		return fmt.Sprintf("waiting for %s's nameservers to serve its own signatures", id)
	}
	switch {
	case !conf.ownSignerSigns(zone):
		return "waiting for this provider's signer to start signing"
	case !servesOwnCopy(instructionsFor(ZoneName(zone)), id) || conf.InternalMp.signerAdds.ownHeld(conf, zone):
		return ""
	}
	return "this provider may switch its servers to its own signer; waiting for its nameservers to serve its own signatures"
}

// ownSignerSigns: this agent's signer says it serves its own signatures.
func (conf *Config) ownSignerSigns(zone string) bool {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return false
	}
	snap := mpzd.GetLastKeyInventory()
	return snap != nil && snap.Signs
}

// servesUnder: the step's sets give id a server role.
func servesUnder(step InstrStep, id string) bool {
	var sets Roles
	if err := json.Unmarshal(step.Sets, &sets); err != nil {
		return false
	}
	return slices.ContainsFunc(sets.Servers, func(p Provider) bool { return core.EqualNames(p.Identity, id) })
}

// servesOwnCopy: under in, id's servers are to serve its own signer's copy: it
// is a server whose record names no upstream but itself. One that names another
// goes on serving that one's, by the owner's word, until an edit moves it.
func servesOwnCopy(in *Instructions, id string) bool {
	label, ok := in.labelOf(id)
	if !ok || !slices.Contains(in.Servers, label) {
		return false
	}
	r, _ := in.record(label)
	return r.Upstream == "" || r.Upstream == label
}

// --- What the agent looks up ---

// signerAddBook is what this agent has looked up for a signer's addition, by
// zone, for the active serial it was looked up under. In memory: after a restart
// it looks again. An agent restarted between its step 3 and its step 4 has no
// serial to hand, and the signed copy lands above what its signer served.
type signerAddBook struct {
	mu    sync.Mutex
	zones map[string]*signerAddLooks
	// start runs a look; nil: in a goroutine of its own. A test runs it in place.
	start func(look func())
}

type signerAddLooks struct {
	serial uint32 // the active serial
	// its nameservers: the highest serial they serve, and whether they serve
	// its own signatures
	served    uint32
	knows     bool
	servedAt  time.Time
	servedRun bool
	own       bool
	ownAt     time.Time
	ownRun    bool
	// the parent's DS RRset, and the largest TTL it was seen with
	parent    parentDSSeen
	parentTTL time.Duration
	parentOK  bool
	parentAt  time.Time
	parentRun bool
	syncAt    time.Time
}

// looksLocked is the zone's looks under its active serial, new when that moved.
func (b *signerAddBook) looksLocked(conf *Config, zone string) *signerAddLooks {
	var serial uint32
	if active, _ := conf.InternalMp.Instructions.activeSerial(zone); active != nil {
		serial = active.Serial
	}
	if b.zones == nil {
		b.zones = map[string]*signerAddLooks{}
	}
	key := canonicalName(zone)
	l := b.zones[key]
	if l == nil || l.serial != serial {
		l = &signerAddLooks{serial: serial}
		b.zones[key] = l
	}
	return l
}

func (b *signerAddBook) run(look func()) {
	if b.start != nil {
		b.start(look)
		return
	}
	go look()
}

// lookCtx is one look's context, with its bound.
func lookCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), transferCheckTimeout)
}

// served is the serial this provider's nameservers last served, under the active
// serial, and whether one is known. Serial 0 is a serial: StartSigning takes 0 as
// none, and lands above what the zone itself served in any case.
func (b *signerAddBook) served(zone string, active uint32) (uint32, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if l := b.zones[canonicalName(zone)]; l != nil && l.serial == active && l.knows {
		return l.served, true
	}
	return 0, false
}

// servedKnown: what its nameservers serve is known. They are asked again every
// transferRecheck meanwhile, and its answer hands the signer the latest.
func (b *signerAddBook) servedKnown(conf *Config, zone string) bool {
	b.mu.Lock()
	l := b.looksLocked(conf, zone)
	due := !l.servedRun && time.Since(l.servedAt) >= transferRecheck
	if due {
		l.servedRun = true
	}
	b.mu.Unlock()
	if due {
		b.run(func() {
			ctx, cancel := lookCtx()
			defer cancel()
			served, err := highestServedSerial(ctx, zone, conf.MpConfig().Local.Nameservers)
			b.mu.Lock()
			l.servedRun, l.servedAt = false, time.Now()
			if err == nil {
				l.served, l.knows = served, true
			}
			b.mu.Unlock()
			if err != nil {
				lg.Debug("what this provider's nameservers serve is not known yet", "zone", zone, "err", err)
				return
			}
			conf.askThaw(zone)
		})
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return l.knows
}

// ownServed: its nameservers serve its own signatures. Checked every
// transferRecheck until they do, and then so for the step.
func (b *signerAddBook) ownServed(conf *Config, zone string) bool {
	b.mu.Lock()
	l := b.looksLocked(conf, zone)
	due := !l.own && !l.ownRun && time.Since(l.ownAt) >= transferRecheck
	if due {
		l.ownRun = true
	}
	b.mu.Unlock()
	if due {
		b.run(func() {
			ctx, cancel := lookCtx()
			defer cancel()
			mp := conf.MpConfig()
			above, known := b.served(zone, l.serial)
			err := servesOwnSignatures(ctx, zone, mp.Local.Nameservers, conf.signerKeys(zone, []string{mp.Identity}), above, known, time.Now())
			b.mu.Lock()
			l.ownRun, l.ownAt, l.own = false, time.Now(), err == nil
			b.mu.Unlock()
			if err != nil {
				lg.Debug("this provider's nameservers do not serve its own signatures yet", "zone", zone, "err", err)
				return
			}
			lg.Info("this provider's nameservers serve its own signatures", "zone", zone, "provider", mp.Identity)
			conf.askThaw(zone)
		})
	}
	return b.ownHeld(conf, zone)
}

func (b *signerAddBook) ownHeld(conf *Config, zone string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.looksLocked(conf, zone).own
}

// parentDS is the parent's DS RRset as last looked at, and whether a look has
// found out. Another is asked once the last is older than signerAddLookEvery.
func (b *signerAddBook) parentDS(conf *Config, zone string) (parentDSSeen, bool) {
	b.mu.Lock()
	l := b.looksLocked(conf, zone)
	due := !l.parentRun && time.Since(l.parentAt) >= signerAddLookEvery
	if due {
		l.parentRun = true
	}
	b.mu.Unlock()
	if due {
		b.run(func() {
			seen, err := parentDSLook(conf, zone)
			b.mu.Lock()
			l.parentRun, l.parentAt = false, time.Now()
			if err == nil {
				l.parent, l.parentOK = seen, true
				l.parentTTL = max(l.parentTTL, seen.ttl)
			}
			b.mu.Unlock()
			if err != nil {
				if conf.InternalMp.reconciles.sayOnce(canonicalName(zone), "parent look "+err.Error()) {
					lg.Warn("what the parent serves for the zone could not be read; a signer's DS step waits", "zone", zone, "err", err)
				}
				return
			}
			conf.askThaw(zone)
		})
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return l.parent, l.parentOK
}

// parentDSTTL is the largest TTL the parent was seen serving the zone's DS RRset
// with under the active serial; 0 when no look has found out, as for a new leader,
// which then has T9's wait alone.
func (b *signerAddBook) parentDSTTL(conf *Config, zone string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.looksLocked(conf, zone).parentTTL
}

// syncDue: it is time to ask the leader's sync again for the zone.
func (b *signerAddBook) syncDue(conf *Config, zone string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.looksLocked(conf, zone)
	if time.Since(l.syncAt) < signerAddSyncEvery {
		return false
	}
	l.syncAt = time.Now()
	return true
}
