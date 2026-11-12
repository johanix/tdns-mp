/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * A signer added (design 5.1, plan S18b, the owner's decisions of 2026-11-03). A
 * provider with no role signs as soon as it is named: no NS record names it, so no
 * validator sees its signatures, and the propagation of keys is meaningless for a
 * zone it does not serve. What must wait is NS records for its servers and its DS.
 * A server that becomes a signer is refused for now (design 5.3). The leader's
 * steps, each confirmed by every voting member:
 *
 *  1. Its keys, and its signing. The joiner enters KeySigners and KeyConfirmers,
 *     and once every member's parts hold that, its signer is handed it too, with
 *     Signing: another signer's combiner would refuse a key from a provider its
 *     sets do not name, and a rejected key waits for its operator. Its signer
 *     starts signing with its first keys, active at once, and sends them to the
 *     other signers, also those it already held. The step waits until its signer
 *     says it signs, and at the leader until every nameserver of the zone serves
 *     its KSK and ZSK, and then for the propagation delay and the largest TTL they
 *     serve the DNSKEY RRset with (signerAddBook.keysPropagated). One that does not
 *     answer has that TTL at least its copy's, and holds nothing, with a warning;
 *     one that answers without the keys holds the step.
 *  2. Its DS. It enters DSSigners, which puts its KSK's DS in the DS set, the leader
 *     syncs under parentsync=agent, and the step waits until the parent serves it,
 *     whoever put it there.
 *  3. The caches' time: the DS TTL at the parent, from when every server there
 *     served its DS.
 *
 * A server role given in the same edit is planned after these (server_role.go),
 * and its nameservers enter Servers only at the last step; given in a later edit,
 * it waits for this transition to be done. An operator's NS records are kept until
 * done (oweIfFrozen). So under nsmgmt=agent nothing names its servers before its
 * DNSKEYs have propagated and its DS is served. Under nsmgmt=owner that is the
 * owner's, and the product holds nothing back (design 3.7, S19's warning).
 *
 * The DS and DNSKEY steps wait for an emergency rollover (design 3.3). A zone nobody
 * signs yet has nothing to validate new keys against, so its first signer has no
 * wait at its keys, and no caches' time after its DS.
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
	mint := plannedStep{key: key(signerAddMint), provider: id, keys: true, what: what(1, "its first keys and its signing, propagated"),
		sets: func(h Roles) Roles {
			h.Signing = addProvider(h.Signing, joiner)
			return h
		},
		wait: func(conf *Config, zone string, _ time.Time) string {
			switch {
			case !conf.joinerKeysIn(zone, id, KeyStateActive):
				return id + " (its KSK and ZSK active)"
			case first:
				return ""
			}
			return conf.InternalMp.signerAdds.keysPropagated(conf, zone, id)
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
			b := &conf.InternalMp.signerAdds
			switch _, known := b.parentDS(conf, zone); {
			case !known:
				return "the parent (the TTL of its DS RRset)"
			case time.Since(since) < b.parentDSTTL(conf, zone):
				return "the DS TTL at the parent, since every server there serves " + id + "'s DS"
			}
			return ""
		}}
	if first {
		return []plannedStep{accept, mint, ds}
	}
	return []plannedStep{accept, mint, ds, caches}
}

// forOwnSigner is what this agent hands its signer of h: at its own provider's
// first step, h without itself in KeySigners and KeyConfirmers, since its signer
// would distribute keys at once and some other signer may not hold the step yet.
// It is handed them at the next step, which the leader takes once every voting
// member holds this one, marked so that keys it already holds go out again.
func (conf *Config) forOwnSigner(zone string, h *ActingHandover) *ActingHandover {
	mp := conf.MpConfig()
	in, ok := conf.InternalMp.Instructions.reconcileInputs(zone)
	if h == nil || mp == nil || !ok || !in.hasStep {
		return h
	}
	id, part, add := signerAddOf(in.step.InstrStep)
	if !add || !core.EqualNames(id, mp.Identity) {
		return h
	}
	if part == signerAddMint {
		c := *h
		c.Joining = true
		return &c
	}
	if part != signerAddAccept {
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
	conf.joinerKeys(zone, id, func(flags uint16, _ uint16, state string, _ *bool, _ *dns.DNSKEY) { note(flags, state) })
	return ksk && zsk
}

// joinerKeys calls each with what this agent knows of each of id's keys: its
// flags, its key tag, its state, its ds and the key, nil if its record can't be
// read.
func (conf *Config) joinerKeys(zone, id string, each func(flags, keytag uint16, state string, ds *bool, key *dns.DNSKEY)) {
	zone = dns.Fqdn(zone)
	if mp := conf.MpConfig(); mp != nil && core.EqualNames(id, mp.Identity) {
		if mpzd, ok := Zones.Get(zone); ok && mpzd != nil {
			if snap := mpzd.GetLastKeyInventory(); snap != nil {
				for _, it := range snap.Inventory {
					if it.State != DnskeyStateForeign {
						rr, _ := dns.NewRR(it.KeyRR)
						key, _ := rr.(*dns.DNSKEY)
						each(it.Flags, it.KeyTag, it.State, it.DS, key)
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
				each(share.dnskeys[i].Flags, st.KeyTag, st.State, st.DS, share.dnskeys[i])
			}
		}
	}
}

// joinerActiveKeys are id's active keys, as this agent knows them, with nil for
// one whose record can't be read.
func (conf *Config) joinerActiveKeys(zone, id string) []*dns.DNSKEY {
	var keys []*dns.DNSKEY
	conf.joinerKeys(zone, id, func(_, _ uint16, state string, _ *bool, key *dns.DNSKEY) {
		if state == KeyStateActive {
			keys = append(keys, key)
		}
	})
	return keys
}

// joinerDSAtParent: the parent, as last looked at, serves at every server the DS
// of a KSK of id whose ds is set. A look is asked while the step waits, and under
// parentsync=agent the leader's sync asked again now and then: explicit, an
// update only where the parent differs. Under parentsync=owner the owner adds
// the DS, and the step's test is the same. Where no server of the parent that
// answers serves any DS of the zone, the zone is unsigned at the parent: no
// validator looks for the joiner's DS, and the step ends at once, whatever the
// scheme (Johan's ruling of 2026-11-05).
func (conf *Config) joinerDSAtParent(zone, id string) bool {
	var ksks []*dns.DNSKEY
	conf.joinerKeys(zone, id, func(flags, _ uint16, _ string, ds *bool, key *dns.DNSKEY) {
		if flags&dns.SEP != 0 && ds != nil && *ds && key != nil {
			ksks = append(ksks, key)
		}
	})
	seen, known := conf.InternalMp.signerAdds.parentDS(conf, zone)
	switch {
	case !known:
	case seen.unsigned:
		if conf.InternalMp.reconciles.sayOnce(canonicalName(zone), "parent unsigned "+canonicalName(id)) {
			lg.Info("the parent serves no DS for the zone; a signer's DS step does not wait", "zone", zone, "provider", id)
		}
		return true
	case slices.ContainsFunc(ksks, seen.serves):
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

// parentDSSeen is what the parent serves of the zone's DS RRset: the records
// that every server that answered holds, whether none of them serves any DS of
// the zone, the largest TTL they gave it, and the servers that did not answer,
// with the last one's error.
type parentDSSeen struct {
	records  map[parentDSRecord]bool
	unsigned bool
	ttl      time.Duration
	silent   []string
	why      error
}

// parentDSRecord is a DS record as served. A key tag says less: 16 bits, and
// another key's DS can have the same.
type parentDSRecord struct {
	tag                   uint16
	algorithm, digestType uint8
	digest                string
}

// serves: the parent serves a DS of key, by whichever digest.
func (s parentDSSeen) serves(key *dns.DNSKEY) bool {
	for r := range s.records {
		if r.tag != key.KeyTag() || r.algorithm != key.Algorithm {
			continue
		}
		if ds := key.ToDS(r.digestType); ds != nil && strings.ToLower(ds.Digest) == r.digest { // not-a-name: a hex digest
			return true
		}
	}
	return false
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
// with the parent's SOA are answers that hold none; a referral, a reply with no
// SOA and any other rcode are no answer (parentDSIn). tdns.AuthQuery makes an
// error of NXDOMAIN.
func askParentDS(zone, server string) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeDS)
	m.SetEdns0(dns.DefaultMsgSize, false)
	res, err := dns.Exchange(m, server)
	if err != nil {
		return nil, err
	}
	return parentDSIn(res, m, server)
}

// parentDSIn is the zone's DS records in a parent server's reply r to query, by
// readServed's rules: only DS records the zone owns count, and a referral or an
// NXDOMAIN with no SOA is no answer, not "no DS". So is a NOERROR with no DS and
// no SOA: the parent's SOA comes with each of its authoritative replies, and a
// server that does not serve the parent zone says nothing of the zone's DS.
func parentDSIn(r, query *dns.Msg, server string) ([]dns.RR, error) {
	rrset, _, err := readServed(r, query, dns.TypeDS)
	switch {
	case err == nil:
		return rrset.RRs, nil
	case !errors.Is(err, errServesNoRRset):
		return nil, fmt.Errorf("%s: %w", server, err)
	case !enclosingSOA(r, query.Question[0].Name):
		return nil, fmt.Errorf("%s: no DS and no SOA in its reply (%s)", server, dns.RcodeToString[r.Rcode])
	}
	return nil, nil
}

// dsAtEveryServer is parentDSSeen from asking each of servers. A validator may
// be handed the DS RRset of any of them, and one without the joiner's DS finds
// nothing to validate its signatures with, so a record counts only if every
// server that answers holds it. One that does not answer is not counted, and is
// named: down, it hands nothing to anyone, but silent to this agent alone it may
// hand others an older RRset. With no answer at all nothing is known.
func dsAtEveryServer(servers []string, ask func(server string) ([]dns.RR, error)) (parentDSSeen, error) {
	var seen parentDSSeen
	served := false
	for _, server := range servers {
		rrs, err := ask(server)
		if err != nil {
			seen.silent, seen.why = append(seen.silent, server), err
			continue
		}
		records := map[parentDSRecord]bool{}
		for _, rr := range rrs {
			if ds, ok := rr.(*dns.DS); ok {
				records[parentDSRecord{ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToLower(ds.Digest)}] = true // not-a-name: a hex digest
				seen.ttl = max(seen.ttl, time.Duration(ds.Hdr.Ttl)*time.Second)
				served = true
			}
		}
		if seen.records != nil {
			maps.DeleteFunc(records, func(r parentDSRecord, _ bool) bool { return !seen.records[r] })
		}
		seen.records = records
	}
	if seen.records != nil {
		seen.unsigned = !served
		return seen, nil
	}
	if seen.why == nil {
		seen.why = errors.New("no parent server is known")
	}
	return parentDSSeen{}, seen.why
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
	// now is the keys' wait's clock; nil: the time. A test moves it.
	now func() time.Time
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
	keys      map[string]*joinerKeysLooks // by the joiner's identity, folded
}

// joinerKeysLooks is what this agent has seen the zone's nameservers serve of a
// joiner's keys.
type joinerKeysLooks struct {
	of      string          // the active keys these looks are of (activeKeysOf)
	with    map[string]bool // those seen with them, folded: one gone quiet has served what it served
	without []string        // those that answered the last look without them
	silent  []string        // those that have answered no look, or answered without them and went quiet
	ttl     time.Duration   // the largest TTL seen: a cache may hold what was served before
	copyTTL time.Duration   // the RRset's TTL in the zone's copy
	since   time.Time       // since when none has held the step; zero while one does
	looked  bool            // a look has found out
	blind   bool            // the latest look found nothing out
	running bool
	at      time.Time
}

// activeKeysOf says which keys these are, whatever their order and TTLs. A nil key,
// one whose record can't be read, says only that.
func activeKeysOf(keys []*dns.DNSKEY) string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == nil {
			ids = append(ids, "?")
			continue
		}
		ids = append(ids, fmt.Sprintf("%d %d %d %s", key.Flags, key.Protocol, key.Algorithm, key.PublicKey))
	}
	slices.Sort(ids)
	return strings.Join(ids, ",")
}

// note takes one look's finding, as of now.
func (k *joinerKeysLooks) note(seen joinerKeysServed, now time.Time) {
	k.ttl, k.copyTTL, k.looked, k.blind = max(k.ttl, seen.ttl), seen.copyTTL, true, false
	with := map[string]bool{}
	for _, ns := range seen.with {
		with[canonicalName(ns)] = true
	}
	k.without, k.silent = seen.without, nil
	for _, ns := range seen.silent {
		if k.with[canonicalName(ns)] {
			with[canonicalName(ns)] = true
		} else {
			k.silent = append(k.silent, ns)
		}
	}
	k.with = with
	switch {
	case len(k.without) > 0:
		k.since = time.Time{}
	case k.since.IsZero():
		k.since = now
	}
}

// waitTTL is the TTL the wait counts: the largest seen, and at least the copy's while
// a nameserver has not answered, which may serve more than the others.
func (k *joinerKeysLooks) waitTTL() time.Duration {
	if len(k.silent) > 0 {
		return max(k.ttl, k.copyTTL)
	}
	return k.ttl
}

// end is when the wait runs out, given the propagation delay.
func (k *joinerKeysLooks) end(delay time.Duration) time.Time {
	return k.since.Add(delay + k.waitTTL())
}

// owesLook: the wait has run out on what the looks that reported before then found.
// It ends only on one that reports since, which may find a nameserver without the
// keys, or nothing.
func (k *joinerKeysLooks) owesLook(delay time.Duration, now time.Time) bool {
	return k.looked && !k.blind && len(k.without) == 0 && !now.Before(k.end(delay)) && k.at.Before(k.end(delay))
}

// waitsFor is what the keys' step waits for at the nameservers, of the joiner id
// ("" for nothing), given the propagation delay.
func (k *joinerKeysLooks) waitsFor(id string, delay time.Duration, now time.Time) string {
	switch {
	case !k.looked || k.blind:
		return "the zone's nameservers (what they serve of " + id + "'s keys, not known yet)"
	case len(k.without) > 0:
		return strings.Join(k.without, ", ") + " (" + id + "'s keys)"
	case now.Before(k.end(delay)):
		return "the propagation delay and the DNSKEY TTL, since the zone's nameservers serve " + id + "'s keys"
	case k.owesLook(delay, now):
		return "a look at the zone's nameservers that reports after the propagation delay and the DNSKEY TTL (" + id + "'s keys)"
	}
	return ""
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

// clock is the time, as the keys' wait reads it.
func (b *signerAddBook) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

// keysPropagated is what the keys' step of the joiner id waits for at the zone's
// nameservers ("" for nothing): each serves its active keys, by the NS RRset of the
// zone's copy, and the DNSKEY RRset has had the propagation delay of the slowest of
// the zone's serving providers and the largest TTL seen since. A look is asked once
// the last is older than signerAddLookEvery, and at once when the wait runs out: it
// ends only on a look that reports since. Kept in memory: a new leader looks again
// and counts from its own look.
func (b *signerAddBook) keysPropagated(conf *Config, zone, id string) string {
	key := canonicalName(id)
	keys := conf.joinerActiveKeys(zone, id)
	of := activeKeysOf(keys)
	delay, _ := conf.delegationNotifyWaitAnnounced(zone)
	b.mu.Lock()
	l := b.looksLocked(conf, zone)
	if l.keys == nil {
		l.keys = map[string]*joinerKeysLooks{}
	}
	k := l.keys[key]
	switch {
	case k == nil:
		k = &joinerKeysLooks{of: of}
		l.keys[key] = k
	case k.of != of:
		// Other active keys: nothing seen was of these, and the wait starts over.
		// A look under way notes in the old k, which is gone. The largest TTL
		// stays, since a cache may hold that RRset.
		k = &joinerKeysLooks{of: of, ttl: k.ttl}
		l.keys[key] = k
	}
	now := b.clock()
	due := !k.running && (now.Sub(k.at) >= signerAddLookEvery || k.owesLook(delay, now))
	if due {
		k.running = true
	}
	b.mu.Unlock()
	if due {
		b.run(func() { b.lookForKeys(conf, zone, id, k, keys) })
	}
	b.mu.Lock()
	wait, ttl := k.waitsFor(id, delay, b.clock()), k.waitTTL()
	b.mu.Unlock()
	if wait == "" && conf.InternalMp.reconciles.sayOnce(canonicalName(zone), "keys propagated "+key) {
		lg.Info("a new signer's keys have propagated", "zone", zone, "provider", id, "delay", delay, "ttl", ttl)
	}
	return wait
}

// lookForKeys runs one look at what the zone's nameservers serve of keys, those of
// the joiner id, and notes it in k.
func (b *signerAddBook) lookForKeys(conf *Config, zone, id string, k *joinerKeysLooks, keys []*dns.DNSKEY) {
	seen, err := joinerKeysServed{}, errors.New("the zone is not here")
	if mpzd, ok := Zones.Get(zone); ok && mpzd != nil {
		seen, err = lookForJoinerKeys(mpzd, keys)
	}
	b.mu.Lock()
	k.running, k.at = false, b.clock()
	wasHeld := k.since.IsZero()
	if err == nil {
		k.note(seen, k.at)
	} else {
		k.blind = true
	}
	cleared := wasHeld && !k.since.IsZero()
	silent, ttl := slices.Clone(k.silent), k.waitTTL()
	b.mu.Unlock()
	say := func(what string) bool {
		return conf.InternalMp.reconciles.sayOnce(canonicalName(zone), "keys look "+canonicalName(id)+" "+what)
	}
	if err != nil {
		if say(err.Error()) {
			lg.Warn("what the zone's nameservers serve could not be looked at; a new signer's keys step waits", "zone", zone, "provider", id, "err", err)
		}
		return
	}
	if len(seen.without) > 0 && say("without "+strings.Join(seen.without, " ")) {
		lg.Info("a nameserver of the zone answers without a new signer's keys; its keys step waits", "zone", zone, "provider", id, "nameservers", seen.without)
	}
	if len(silent) > 0 && say("silent "+strings.Join(silent, " ")) {
		lg.Warn("a nameserver of the zone does not answer; a new signer's keys step does not wait for it, and waits at least the TTL of the zone's copy", "zone", zone, "provider", id, "nameservers", silent, "err", seen.why)
	}
	if cleared {
		delay, _ := conf.delegationNotifyWaitAnnounced(zone)
		lg.Info("the zone's nameservers serve a new signer's keys; its keys step waits the propagation delay and their TTL", "zone", zone, "provider", id, "delay", delay, "ttl", ttl)
	}
	conf.askThaw(zone)
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
			if len(seen.silent) > 0 && conf.InternalMp.reconciles.sayOnce(canonicalName(zone), "parent silent "+strings.Join(seen.silent, " ")) {
				lg.Warn("a server of the parent does not answer; a signer's DS step does not wait for it", "zone", zone, "servers", seen.silent, "err", seen.why)
			}
			conf.askThaw(zone)
		})
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return l.parent, l.parentOK
}

// parentDSTTL is the largest TTL the parent was seen serving the zone's DS RRset
// with under the active serial; 0 when no look has found out.
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
