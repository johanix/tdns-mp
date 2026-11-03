/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A signer added (design 5.1, plan S18b, the owner's decision of 2026-11-03). A
 * provider with no role signs as soon as it is named: no NS record names it, so
 * no validator sees its signatures, and what must wait is NS records for its
 * servers. A server that becomes a signer is refused for now (design 5.3). The
 * leader's steps, each confirmed by every voting member:
 *
 *  1. Its keys, and its signing. The joiner enters KeySigners and KeyConfirmers,
 *     and once every member's parts hold that, its signer is handed it too, with
 *     Signing: another signer's combiner would refuse a key from a provider its
 *     sets do not name, and a rejected key waits for its operator. Its key machine
 *     makes its first keys (which a hold lets it: a role with no active key gets
 *     one), which sign from the start, and distributes them; its signer starts
 *     signing. The step waits until its key states show a KSK and a ZSK published,
 *     which needs every other signer to have applied them, and until its signer
 *     says it signs.
 *  2. Its DS. It enters DSSigners. Its KSK's ds=1, set once the DNSKEY RRset has
 *     propagated (T8), puts its DS in the DS set, the leader syncs under
 *     parentsync=agent, and the step waits until the parent serves it, whoever put
 *     it there.
 *  3. The caches' time. Its key machine waits the DS TTL at the parent before its
 *     KSK goes active (T9), asking one server: the step waits until its key states
 *     show them active, and for the DS TTL from when every server served its DS.
 *
 * A server role given in the same edit is planned after these (server_role.go),
 * and its nameservers enter Servers only at the last step; given in a later edit,
 * it waits for this transition to be done. An operator's NS records are kept until
 * done (oweIfFrozen). So under nsmgmt=agent nothing names its servers before its
 * DNSKEYs have propagated and its DS is served. Under nsmgmt=owner that is the
 * owner's (design 3.7).
 *
 * The DS and DNSKEY steps wait for an emergency rollover (design 3.3). With no
 * provider signing yet there are no signatures to go with a DS: the zone's first
 * signer has its caches' time before its DS goes to the parent.
 */
package tdnsmp

import (
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
		first := !slices.ContainsFunc(p.held.Signing, func(o Provider) bool { return !core.EqualNames(o.Identity, s.Identity) })
		steps = append(steps, signerAddStepsOf(s, first)...)
	}
	return steps
}

// signerAddStepsOf are the steps of the provider joiner; first, a provider that
// joins a zone nobody else signs.
func signerAddStepsOf(joiner Provider, first bool) []plannedStep {
	id := joiner.Identity
	key := func(part string) string { return signerAddKey + part + " " + canonicalName(id) }
	what := func(n int, part string) string { return fmt.Sprintf("adding signer %s: step %d (%s)", id, n, part) }
	accept := plannedStep{key: key(signerAddAccept), provider: id, keys: true, what: what(1, "the other signers take its keys"),
		sets: func(h Roles) Roles {
			h.KeySigners, h.KeyConfirmers = addProvider(h.KeySigners, joiner), addProvider(h.KeyConfirmers, joiner)
			return h
		}}
	mint := plannedStep{key: key(signerAddMint), provider: id, keys: true, what: what(1, "its first keys, published, and its signing"),
		sets: func(h Roles) Roles {
			h.Signing = addProvider(h.Signing, joiner)
			return h
		},
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
	if first {
		return []plannedStep{accept, mint, caches, ds}
	}
	return []plannedStep{accept, mint, ds, caches}
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

// signerAddHolds: at the provider's own agent, its keys' step is held once its
// signer signs. Every other agent's part is its parts holding the step's sets.
func signerAddHolds(conf *Config, zone string, step InstrStep) bool {
	id, part, ok := signerAddOf(step)
	mp := conf.MpConfig()
	if !ok || mp == nil || !core.EqualNames(id, mp.Identity) || part != signerAddMint {
		return true
	}
	return conf.ownSignerSigns(zone)
}

// signerAddStatus is what a signer's step waits for that the leader's view does
// not say: at the provider's own agent, its signer.
func signerAddStatus(conf *Config, zone string, step heldStep, _ time.Time) string {
	if signerAddHolds(conf, zone, step.InstrStep) {
		return ""
	}
	return "waiting for this provider's signer to start signing"
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

// --- What the agent looks up ---

// signerAddBook is what this agent has looked up for a signer's addition, by
// zone, for the active serial it was looked up under. In memory: after a restart
// it looks again.
type signerAddBook struct {
	mu    sync.Mutex
	zones map[string]*signerAddLooks
	// start runs a look; nil: in a goroutine of its own. A test runs it in place.
	start func(look func())
}

type signerAddLooks struct {
	serial uint32 // the active serial
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
