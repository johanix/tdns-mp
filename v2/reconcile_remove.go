/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The removal (design 5.2, plan S17b): the runner for a transition that takes
 * a provider out of servers=, signers= or both. The leader under V runs it,
 * needing nothing from the leaving provider, one step at a time:
 *
 *  1. Its NS names are named, from its stamp and the parent's NS RRset, and
 *     kept on disk by every agent. The roll of the zone's key is owed: an
 *     obligation, not a gate. A signer that serves nothing leaves
 *     KeyConfirmers here, at the reconciliation's first step.
 *  2. If it leaves servers=: Servers drop it, its NS is withdrawn under
 *     nsmgmt=agent, the leader syncs and watches the parent until no server of
 *     its names the names, and counts the NS TTLs from then. Then it leaves
 *     KeyConfirmers.
 *  3. If it leaves signers=: DSSigners drop it, its CDS is withdrawn, the
 *     leader syncs and watches the parent until no server of its serves its
 *     DS, and waits the DS TTL and parent-publish-delay from then.
 *  4. Its DNSKEY is withdrawn; KeySigners and Signing drop it: it stops
 *     signing.
 *  5. The removal is done: every agent drops it from disk.
 *
 * Steps 3 and 4 wait for an emergency rollover (design 3.3). The plan is made
 * from what is in place: the sets held, the removals on disk and the steps
 * taken, so a new leader plans the same steps from the stamps it took.
 */
package tdnsmp

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func init() {
	registerStepRunner(stepRunner{name: "removal", kind: stepRemoval, steps: removalSteps})
}

const (
	// parentLookEvery is how often the leader looks at what the parent serves
	// while a removal watches it.
	parentLookEvery = 15 * time.Second
	// stepSyncEvery is how often a step that watches the parent asks the sync
	// again: the zone's copy may follow the withdrawal only after the first.
	stepSyncEvery = time.Minute
	// removalTTLUnknown stands for a TTL this agent never saw served: a new
	// leader's, of a DS the parent had dropped before it looked.
	removalTTLUnknown = time.Hour
)

// leaver is a provider that leaves servers=, signers= or both.
type leaver struct {
	Provider
	servers, signers bool // the lists it leaves
}

func removalKey(label, part string) string { return "remove " + label + " " + part }

// removalKeyParts are the label and the part of a removal's step key; false
// for a key that is no removal's.
func removalKeyParts(key string) (label, part string, ok bool) {
	f := strings.Fields(key)
	if len(f) != 3 || f[0] != "remove" {
		return "", "", false
	}
	return f[1], f[2], true
}

// leaversOf are the zone's leaving providers, by label: those the sets held
// name and V's lists do not, and those whose steps are already taken or whose
// removal is on disk, whom the sets may no longer name. A label with no ON
// record names nobody, and has no removal.
func leaversOf(p planView) []leaver {
	if p.to == nil {
		return nil
	}
	byLabel := map[string]*leaver{}
	note := func(label, identity string, servers, signers bool) {
		label = strings.TrimSuffix(label, ".")
		l := byLabel[label]
		if l == nil {
			l = &leaver{Provider: Provider{Label: label}}
			byLabel[label] = l
		}
		if l.Identity == "" {
			l.Identity = identity
		}
		l.servers, l.signers = l.servers || servers, l.signers || signers
	}
	for _, pr := range p.held.Servers {
		if !slices.Contains(p.to.Servers, strings.TrimSuffix(pr.Label, ".")) {
			note(pr.Label, pr.Identity, true, false)
		}
	}
	for _, set := range [][]Provider{p.held.KeySigners, p.held.DSSigners, p.held.KeyConfirmers, p.held.Signing} {
		for _, pr := range set {
			if !slices.Contains(p.to.Signers, strings.TrimSuffix(pr.Label, ".")) {
				note(pr.Label, pr.Identity, false, true)
			}
		}
	}
	for _, r := range p.removals {
		note(r.Label, r.Identity, false, false)
	}
	for _, key := range p.taken {
		if label, part, ok := removalKeyParts(key); ok {
			note(label, "", part == "ns" || part == "confirmers", part == "ds" || part == "dnskey")
		}
	}
	var out []leaver
	for _, l := range byLabel {
		if l.Identity == "" {
			l.Identity = recordIdentity(l.Label, p.from, p.to)
		}
		if l.Identity != "" {
			out = append(out, *l)
		}
	}
	slices.SortFunc(out, func(a, b leaver) int { return cmp.Compare(a.Label, b.Label) })
	return out
}

// recordIdentity is the identity of the ON record with the label, under the
// first of the readings that has one.
func recordIdentity(label string, readings ...*Instructions) string {
	for _, in := range readings {
		if in == nil {
			continue
		}
		if id := in.identityOf(label); id != "" {
			return id
		}
	}
	return ""
}

// removalSteps is the runner's plan: each leaving provider's steps, one
// provider after the other.
func removalSteps(p planView) []plannedStep {
	var out []plannedStep
	for _, l := range leaversOf(p) {
		out = append(out, l.steps(p)...)
	}
	return out
}

func withoutProvider(set []Provider, label string) []Provider {
	return slices.DeleteFunc(slices.Clone(set), func(pr Provider) bool { return strings.TrimSuffix(pr.Label, ".") == label })
}

func withoutRemoval(rs []Removal, label string) []Removal {
	return slices.DeleteFunc(slices.Clone(rs), func(r Removal) bool { return r.Label == label })
}

func (l leaver) steps(p planView) []plannedStep {
	label, id := l.Label, l.Identity
	head := "removing " + id
	agentNS := p.held.NSmgmt == core.HsyncNSmgmtAGENT
	names := plannedStep{
		key: removalKey(label, "names"), what: head + ", step 1 (its NS names)", provider: id, leaverNS: true,
		first: !l.servers,
		removals: func(held []Removal) []Removal {
			var ns []string
			if l.servers && p.conf != nil {
				ns = p.conf.leavingNSNames(p, id)
			}
			return append(withoutRemoval(held, label), Removal{Label: label, Identity: id, NSNames: ns})
		},
		start: func(conf *Config, zone string) {
			if conf.InternalMp.reconciles.sayOnce(canonicalName(zone), removalRollOwed) {
				oweRemovalRoll(conf, ZoneName(zone))
			}
			logRemovalStep(zone, id, "1 (its NS names)", "")
		},
	}
	if l.servers {
		names.ready = func(conf *Config, zone string) string {
			if _, ok := conf.parentNow(zone); !ok {
				return "until the parent's NS RRset is known"
			}
			return ""
		}
	} else if l.signers {
		// a signer that serves nothing leaves the confirmers at the first step,
		// excused or not (design 5)
		names.sets = func(held Roles) Roles {
			held.KeyConfirmers = withoutProvider(held.KeyConfirmers, label)
			return held
		}
	}
	out := []plannedStep{names}
	if l.servers {
		what := head + ", step 2 (its NS)"
		if p.excused[canonicalName(id)] {
			what = head + " (excused): its NS first"
		}
		out = append(out, plannedStep{
			key: removalKey(label, "ns"), what: what, provider: id, leaverNS: true,
			sets: func(held Roles) Roles {
				held.Servers = withoutProvider(held.Servers, label)
				return held
			},
			start: func(conf *Config, zone string) {
				if agentNS {
					askWithdrawal(conf, zone, Withdraw{Provider: id, RRtype: "NS"})
				}
				logRemovalStep(zone, id, "2 (its NS)", "")
			},
			wait: func(conf *Config, zone string, _ time.Time) string {
				return conf.removalNSWait(zone, label, id, agentNS)
			},
		})
		if l.signers {
			out = append(out, plannedStep{
				key: removalKey(label, "confirmers"), what: head + ", step 2 (its NS): it leaves the key confirmers", provider: id, leaverNS: true,
				sets: func(held Roles) Roles {
					held.KeyConfirmers = withoutProvider(held.KeyConfirmers, label)
					return held
				},
				start: func(conf *Config, zone string) {
					logRemovalStep(zone, id, "2 (its NS): it leaves the key confirmers", "")
					conf.lookAgainAtDnskeyWaits(ZoneName(zone))
				},
			})
		}
	}
	if l.signers {
		out = append(out, plannedStep{
			key: removalKey(label, "ds"), what: head + ", step 3 (its DS)", provider: id, keys: true,
			sets: func(held Roles) Roles {
				held.DSSigners = withoutProvider(held.DSSigners, label)
				return held
			},
			start: func(conf *Config, zone string) {
				askWithdrawal(conf, zone, Withdraw{Provider: id, RRtype: "CDS"})
				logRemovalStep(zone, id, "3 (its DS)", "")
			},
			wait: func(conf *Config, zone string, _ time.Time) string {
				return conf.removalDSWait(zone, label, id)
			},
		}, plannedStep{
			key: removalKey(label, "dnskey"), what: head + ", step 4 (its DNSKEY)", provider: id, keys: true,
			sets: func(held Roles) Roles {
				held.KeySigners = withoutProvider(held.KeySigners, label)
				held.Signing = withoutProvider(held.Signing, label)
				return held
			},
			start: func(conf *Config, zone string) {
				askWithdrawal(conf, zone, Withdraw{Provider: id, RRtype: "DNSKEY"})
				logRemovalStep(zone, id, "4 (its DNSKEY)", "")
			},
			wait: func(conf *Config, zone string, _ time.Time) string {
				if !conf.removalWithdrawn(zone, id, "DNSKEY") {
					return "for the withdrawal of its DNSKEY to be confirmed"
				}
				return ""
			},
		})
	}
	return append(out, plannedStep{
		key: removalKey(label, "done"), what: head + ", done", provider: id,
		removals: func(held []Removal) []Removal { return withoutRemoval(held, label) },
		start:    func(_ *Config, zone string) { logRemovalStep(zone, id, "5 (done)", "") },
	})
}

// logRemovalStep is the line of a step taken, or of what it waits until.
func logRemovalStep(zone, provider, step, until string) {
	lg.Info("removal step", "zone", zone, "provider", provider, "step", step, "until", until)
}

// removalRollOwed is the book's mark that this agent has owed the roll in this
// transition: once, for all its removals.
const removalRollOwed = "the roll is owed"

// oweRemovalRoll keeps the roll of the zone's key as owed at the removal's
// first step (S17a); a test stands in for it.
var oweRemovalRoll = func(conf *Config, zone ZoneName) { conf.oweRoll(zone) }

// --- The names ---

// leavingNSNames are the leaving provider's NS names (design 5.2): those it
// tells in its stamp, and those the parent's NS RRset holds at the removal's
// start that no other provider tells or contributes and, under nsmgmt=owner,
// that the owner's NS RRset under V does not name (7.2). They are not taken
// from what this agent's data holds of it. A name given to the wrong provider
// only holds the step, safely, and the status names it.
func (conf *Config) leavingNSNames(p planView, id string) []string {
	var t *stampTable
	if tm := conf.InternalMp.MPTransport; tm != nil {
		t = tm.stamps
	}
	names := t.toldNameservers(id)
	others := map[string]bool{}
	for _, n := range t.othersNameservers(id) {
		others[canonicalName(n)] = true
	}
	if mp := conf.MpConfig(); mp != nil {
		for _, n := range mp.Local.Nameservers {
			others[canonicalName(n)] = true
		}
	}
	if zdr := conf.InternalMp.ZoneDataRepo; zdr != nil {
		if repo, ok := zdr.Get(ZoneName(p.zone)); ok {
			for agent, od := range repo.Data.Items() {
				if od == nil || sameName(string(agent), id) {
					continue
				}
				if rrset, ok := od.RRtypes.Get(dns.TypeNS); ok {
					for _, rr := range rrset.RRs {
						if ns, ok := rr.(*dns.NS); ok {
							others[canonicalName(ns.Ns)] = true
						}
					}
				}
			}
		}
	}
	if p.held.NSmgmt != core.HsyncNSmgmtAGENT {
		ownerNS, _ := zoneNSOf(p.zone)
		for _, n := range ownerNS {
			others[canonicalName(n)] = true
		}
	}
	seen, _ := conf.parentNow(p.zone)
	for _, n := range seen.ns {
		if !others[canonicalName(n)] {
			names = append(names, n)
		}
	}
	for i := range names {
		names[i] = canonicalName(names[i])
	}
	return sortedUnique(names)
}

// zoneNSOf is the zone's own NS RRset, as this agent's copy holds it: its
// names, and its TTL.
func zoneNSOf(zone string) ([]string, uint32) {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil || mpzd.ZoneData == nil {
		return nil, 0
	}
	apex, err := mpzd.GetOwner(mpzd.ZoneName)
	if err != nil || apex == nil {
		return nil, 0
	}
	var names []string
	var ttl uint32
	for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs {
		if ns, ok := rr.(*dns.NS); ok {
			names = append(names, canonicalName(ns.Ns))
			ttl = max(ttl, ns.Hdr.Ttl)
		}
	}
	return names, ttl
}

// --- The parent ---

// parentSeen is what the parent serves for the zone, as last looked at. A
// resolver may be handed the answer of any of its servers, so a record is still
// served while one server that answers holds it: the fields read all the answers
// together, and each keeps them apart.
type parentSeen struct {
	at       time.Time
	ns       []string     // the names of its NS RRset, folded
	nsTTL    uint32       // the largest
	nsServer string       // the parent's server that gave it
	ds       []uint16     // the key tags of its DS RRset
	dsRRs    []*dns.DS    // the same RRset, whole
	dsTTL    uint32       // the largest, as last served
	noNS     bool         // of one server: its NS query failed, so it tells nothing of them
	noDS     bool         // of one server: it tells nothing of its DS (parentAtEveryServer)
	each     []parentSeen // what each server that answered serves
}

func (one parentSeen) toldNS() bool { return !one.noNS }
func (one parentSeen) toldDS() bool { return !one.noDS }

// parentLook asks the parent what it serves for the zone; a test stands in
// for it. It asks the servers AnalyseZoneDelegation asks.
var parentLook = func(conf *Config, zone string) (parentSeen, error) {
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil || mpzd.ZoneData == nil {
		return parentSeen{}, fmt.Errorf("zone %s is not here", zone)
	}
	zd := mpzd.ZoneData
	if conf.Config == nil || conf.Config.Internal.ImrEngine == nil {
		return parentSeen{}, fmt.Errorf("no resolver to ask the parent of %s with yet", zone)
	}
	if err := zd.FetchParentData(conf.Config.Internal.ImrEngine); err != nil {
		return parentSeen{}, err
	}
	seen, err := parentAtEveryServer(zd.ParentServers, func(server string, rrtype uint16) ([]dns.RR, error) {
		return tdns.AuthQuery(zd.ZoneName, server, rrtype)
	})
	if err != nil {
		return parentSeen{}, fmt.Errorf("zone %s: %w", zd.ZoneName, err)
	}
	return seen, nil
}

// parentAtEveryServer is parentSeen from asking each of servers. A server tells
// what it answers and hands out nothing else: one whose DS query fails still
// tells its NS RRset, and one whose NS query fails still tells a DS RRset it
// serves, though not that it serves none, as only an NS RRset shows it holds the
// zone. One with no NS RRset for the zone tells nothing of it. With no server
// telling the NS RRset, or none telling the DS, that is not known, and the look
// has found nothing out: the last one stands.
func parentAtEveryServer(servers []string, ask func(server string, rrtype uint16) ([]dns.RR, error)) (parentSeen, error) {
	var seen parentSeen
	var last error
	for _, server := range servers {
		nsrrs, nsErr := ask(server, dns.TypeNS)
		if nsErr != nil {
			last = nsErr
		} else if len(nsrrs) == 0 {
			continue
		}
		dsrrs, dsErr := ask(server, dns.TypeDS)
		if dsErr != nil {
			last = dsErr
		}
		one := serverSeen(server, nsrrs, dsrrs)
		one.noNS = nsErr != nil
		one.noDS = dsErr != nil || (nsErr != nil && len(dsrrs) == 0)
		if one.toldNS() || one.toldDS() {
			seen.add(one)
		}
	}
	if slices.ContainsFunc(seen.each, parentSeen.toldNS) && slices.ContainsFunc(seen.each, parentSeen.toldDS) {
		return seen, nil
	}
	if last == nil {
		last = errors.New("no parent server gave an NS RRset")
	}
	return parentSeen{}, last
}

// serverSeen is what one server of the parent answered.
func serverSeen(server string, nsrrs, dsrrs []dns.RR) parentSeen {
	seen := parentSeen{nsServer: server}
	for _, rr := range nsrrs {
		if ns, ok := rr.(*dns.NS); ok {
			seen.ns = append(seen.ns, canonicalName(ns.Ns))
			seen.nsTTL = max(seen.nsTTL, ns.Hdr.Ttl)
		}
	}
	for _, rr := range dsrrs {
		if ds, ok := rr.(*dns.DS); ok {
			seen.ds = append(seen.ds, ds.KeyTag)
			seen.dsRRs = append(seen.dsRRs, ds)
			seen.dsTTL = max(seen.dsTTL, ds.Hdr.Ttl)
		}
	}
	return seen
}

// add reads one more server's answer into seen.
func (seen *parentSeen) add(one parentSeen) {
	seen.each = append(seen.each, one)
	for _, name := range one.ns {
		if !slices.Contains(seen.ns, name) {
			seen.ns = append(seen.ns, name)
		}
	}
	for _, ds := range one.dsRRs {
		if !slices.ContainsFunc(seen.dsRRs, func(held *dns.DS) bool { return dns.IsDuplicate(held, ds) }) {
			seen.ds = append(seen.ds, ds.KeyTag)
			seen.dsRRs = append(seen.dsRRs, ds)
		}
	}
	if one.toldNS() && (seen.nsServer == "" || one.nsTTL > seen.nsTTL) {
		seen.nsTTL, seen.nsServer = one.nsTTL, one.nsServer
	}
	seen.dsTTL = max(seen.dsTTL, one.dsTTL)
}

// behind are the servers holding what holds asks of, while another that told of
// it does not: the parent has dropped it and they have yet to follow. Sorted;
// none while every server that told holds it, as no server is behind then.
func (seen parentSeen) behind(told, holds func(one parentSeen) bool) []string {
	var servers []string
	telling := 0
	for _, one := range seen.each {
		if !told(one) {
			continue
		}
		telling++
		if holds(one) {
			servers = append(servers, one.nsServer)
		}
	}
	if len(servers) == telling {
		return nil
	}
	slices.Sort(servers)
	return servers
}

// behindSaid is what a watch on the parent adds to the step's status for the
// servers behind, "" with none.
func behindSaid(servers []string) string {
	if len(servers) == 0 {
		return ""
	}
	return " (still at " + strings.Join(servers, ", ") + "; the parent's other servers have dropped it)"
}

// parentLookGo runs a look at the parent; a test runs it in place.
var parentLookGo = func(look func()) { go look() }

// parentNow is what the parent last served for the zone, false when no look
// has found out yet. A look is asked when the last is older than
// parentLookEvery; its answer brings a turn.
func (conf *Config) parentNow(zone string) (parentSeen, bool) {
	rb := &conf.InternalMp.reconciles
	key := canonicalName(zone)
	now := time.Now()
	rb.mu.Lock()
	zr := rb.zone(key)
	due := !zr.looking && now.Sub(zr.lookedAt) >= parentLookEvery
	if due {
		zr.looking, zr.lookedAt = true, now
	}
	rb.mu.Unlock()
	if due {
		parentLookGo(func() {
			got, err := parentLook(conf, zone)
			rb.mu.Lock()
			zr := rb.zone(key)
			zr.looking = false
			if err == nil {
				got.at = time.Now()
				if got.dsTTL == 0 {
					got.dsTTL = zr.parent.dsTTL // as last served
				}
				zr.parent = got
			}
			rb.mu.Unlock()
			if err != nil {
				if rb.sayOnce(key, "parent look "+err.Error()) {
					lg.Warn("what the parent serves for the zone could not be read; a removal's step waits", "zone", zone, "err", err)
				}
				return
			}
			conf.askThaw(zone)
		})
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	seen := rb.zone(key).parent
	return seen, !seen.at.IsZero()
}

// sinceFirst is when the zone's named wait was first asked of here, now if
// never: a wait whose start is not known starts now (S17b).
func (b *reconcileBook) sinceFirst(zone, wait string, now time.Time) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	zr := b.zone(zone)
	if t, ok := zr.since[wait]; ok {
		return t
	}
	if zr.since == nil {
		zr.since = map[string]time.Time{}
	}
	zr.since[wait] = now
	return now
}

// forgetWait starts the zone's named wait over: what it counted from is no
// longer so.
func (b *reconcileBook) forgetWait(zone, wait string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.zone(zone).since, wait)
}

// --- The withdrawal, on the data engine ---

// askWithdrawal asks the data engine for the plan's withdrawal, and to say
// whether it is done (planWithdraw); a test stands in for it. Asked at every
// turn while it is not done, so a queue that is full now is asked again.
var askWithdrawal = func(conf *Config, zone string, w Withdraw) {
	msgQs := conf.InternalMp.MsgQs
	if msgQs == nil || msgQs.SynchedDataCmd == nil {
		return
	}
	select {
	case msgQs.SynchedDataCmd <- &SynchedDataCmd{Cmd: "plan-withdraw", Zone: ZoneName(zone), Withdraw: &w}:
	default:
	}
}

func withdrawnKey(provider, rrtype string) string { return canonicalName(provider) + " " + rrtype }

// planWithdraw is the removal's call on the data engine: the withdrawal goes
// if what is in place here still calls for one, and the book learns whether it
// is done. A new leader that took the step comes here by the step's wait.
func (conf *Config) planWithdraw(zdr *ZoneDataRepo, zone ZoneName, w *Withdraw) {
	provider := AgentId(w.Provider)
	if _, err := conf.withdraw(zdr, zone, provider, w.RRtype); err != nil {
		lgEngine.Warn("a removal's withdrawal could not be sent; the step's turn asks again", "zone", zone, "provider", provider, "rrtype", w.RRtype, "err", err)
		return
	}
	if !conf.withdrawalDone(zdr, zone, provider, w.RRtype) {
		return
	}
	rb := &conf.InternalMp.reconciles
	rb.mu.Lock()
	zr := rb.zone(canonicalName(string(zone)))
	if zr.withdrawn == nil {
		zr.withdrawn = map[string]bool{}
	}
	zr.withdrawn[withdrawnKey(w.Provider, w.RRtype)] = true
	rb.mu.Unlock()
	conf.askThaw(string(zone))
}

// removalWithdrawn: the withdrawal of provider's records of rrtype is done, as
// the data engine last said. While it is not, the engine is asked.
func (conf *Config) removalWithdrawn(zone, provider, rrtype string) bool {
	rb := &conf.InternalMp.reconciles
	rb.mu.Lock()
	done := rb.zone(canonicalName(zone)).withdrawn[withdrawnKey(provider, rrtype)]
	rb.mu.Unlock()
	if !done {
		askWithdrawal(conf, zone, Withdraw{Provider: provider, RRtype: rrtype})
	}
	return done
}

// --- The sync ---

// askStepSync asks the leader's sync as a step's own, which passes the freeze
// (syncCauseFor), at most every stepSyncEvery.
func (conf *Config) askStepSync(zone, why string) {
	rb := &conf.InternalMp.reconciles
	now := time.Now()
	rb.mu.Lock()
	zr := rb.zone(canonicalName(zone))
	due := now.Sub(zr.syncAt) >= stepSyncEvery
	zr.stepSync = true
	if due {
		zr.syncAt = now
	}
	rb.mu.Unlock()
	if due {
		// the sync may wait for the zone's key, whose offers now pass
		// (offerHeld): the key rounds look at once
		conf.InternalMp.CatchUp.keyCheck(ZoneName(zone))
		stepSyncAsk(conf, zone, why)
	}
}

// stepSyncAsk asks the leader's delegation sync; a test stands in for it.
var stepSyncAsk = func(conf *Config, zone, why string) { conf.requestDelegationSync(nil, zone, why) }

// asksSync: the step held asks the leader's sync, so a sync of the zone is the
// step's own.
func (b *reconcileBook) asksSync(zone string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	zr := b.zones[zone]
	return zr != nil && zr.stepSync
}

// stepTaken: the next step is taken, which asks its own sync, if any.
func (b *reconcileBook) stepTaken(zone string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if zr := b.zones[zone]; zr != nil {
		zr.stepSync, zr.syncAt, zr.watching = false, time.Time{}, ""
	}
}

// --- The waits ---

// removalNSWait is what the leaving provider's NS step waits for: under
// nsmgmt=agent the withdrawal's confirmations; then until no server of the
// parent names the stored names, and from then the longer of the two ways a
// resolver can still reach the provider: the parent's NS TTL plus
// parent-publish-delay, and the zone's NS TTL plus the propagation delay. The
// leader's operator's word ends the watch, not what follows it. "" once passed.
func (conf *Config) removalNSWait(zone, label, id string, agentNS bool) string {
	if agentNS && !conf.removalWithdrawn(zone, id, "NS") {
		return "for the withdrawal of its NS to be confirmed"
	}
	rb := &conf.InternalMp.reconciles
	key := canonicalName(zone)
	step := removalKey(label, "ns")
	word := conf.InternalMp.Instructions.parentWord(zone, step)
	seen, ok := conf.parentNow(zone)
	if !ok && !word {
		conf.askStepSync(zone, "a removal's NS step")
		rb.watches(key, step)
		return "until the parent's NS RRset is known"
	}
	wait := "ns " + label
	rm, _ := conf.InternalMp.Instructions.removal(zone, label, "")
	var named []string
	for _, n := range rm.NSNames {
		if slices.Contains(seen.ns, canonicalName(n)) {
			named = append(named, n)
		}
	}
	zoneNames, zoneTTL := zoneNSOf(zone)
	if len(named) > 0 && !word {
		conf.askStepSync(zone, "a removal's NS step")
		rb.forgetWait(key, wait)
		rb.watches(key, step)
		text := "until the parent no longer names " + strings.Join(named, ", ")
		if !agentNS && slices.ContainsFunc(named, func(n string) bool { return slices.Contains(zoneNames, canonicalName(n)) }) {
			text += " (the owner's NS RRset still names it)"
		}
		text += behindSaid(seen.behind(parentSeen.toldNS, func(one parentSeen) bool {
			return slices.ContainsFunc(named, func(n string) bool { return slices.Contains(one.ns, canonicalName(n)) })
		}))
		return removalWaitSaid(conf, zone, id, "2 (its NS)", text+conf.parentRefusalNote(zone, id, step))
	}
	rb.watches(key, "")
	delay, largest := conf.delegationNotifyWait(zone)
	publish := parentPublishDelayFor(conf.MpConfig())
	since := rb.sinceFirst(key, wait, time.Now())
	until := since.Add(max(time.Duration(seen.nsTTL)*time.Second+publish, time.Duration(zoneTTL)*time.Second+delay))
	// the wait's terms as they are read, and again if one of them changes
	if rb.sayOnce(key, fmt.Sprintf("%s terms %d %s %s %d %s %s", wait, seen.nsTTL, seen.nsServer, publish, zoneTTL, delay, since)) {
		lg.Info("a removal's NS step counts its wait", "zone", zone, "provider", id, "parent_ns_ttl", seen.nsTTL, "parent_server", seen.nsServer, "parent_publish_delay", publish,
			"zone_ns_ttl", zoneTTL, "delay", delay, "delay_from", largest, "since", since.UTC().Format(time.RFC3339), "until", until.UTC().Format(time.RFC3339))
	}
	if time.Now().Before(until) {
		return removalWaitSaid(conf, zone, id, "2 (its NS)", "for the NS TTL until "+removalTime(until))
	}
	return ""
}

// removalDSWait is what the leaving provider's DS step waits for: its CDS
// withdrawn, then until no server of the parent serves its DS, and from then the
// parent's DS TTL, as last served, plus parent-publish-delay. The leader's
// operator's word ends the watch, not what follows it. "" once passed.
func (conf *Config) removalDSWait(zone, label, id string) string {
	if !conf.removalWithdrawn(zone, id, "CDS") {
		return "for the withdrawal of its CDS to be confirmed"
	}
	rb := &conf.InternalMp.reconciles
	key := canonicalName(zone)
	step := removalKey(label, "ds")
	word := conf.InternalMp.Instructions.parentWord(zone, step)
	seen, ok := conf.parentNow(zone)
	if !ok && !word {
		conf.askStepSync(zone, "a removal's DS step")
		rb.watches(key, step)
		return "until the parent's DS RRset is known"
	}
	wait := "ds " + id
	if !word && !dsLeft(conf, zone, seen) {
		conf.askStepSync(zone, "a removal's DS step")
		rb.forgetWait(key, wait)
		rb.watches(key, step)
		text := behindSaid(seen.behind(parentSeen.toldDS, func(one parentSeen) bool { return !dsLeft(conf, zone, one) }))
		return removalWaitSaid(conf, zone, id, "3 (its DS)", "until the parent no longer serves its DS"+text+conf.parentRefusalNote(zone, id, step))
	}
	rb.watches(key, "")
	ttl := removalTTLUnknown
	if seen.dsTTL != 0 {
		ttl = time.Duration(seen.dsTTL) * time.Second
	}
	publish := parentPublishDelayFor(conf.MpConfig())
	since := rb.sinceFirst(key, wait, time.Now())
	until := since.Add(ttl + publish)
	// the wait's terms as they are read, and again if one of them changes
	if rb.sayOnce(key, fmt.Sprintf("%s terms %s %s %s", wait, ttl, publish, since)) {
		lg.Info("a removal's DS step counts its wait", "zone", zone, "provider", id, "parent_ds_ttl", ttl, "ttl_seen", seen.dsTTL != 0, "parent_publish_delay", publish,
			"since", since.UTC().Format(time.RFC3339), "until", until.UTC().Format(time.RFC3339))
	}
	if time.Now().Before(until) {
		return removalWaitSaid(conf, zone, id, "3 (its DS)", "for the DS TTL until "+removalTime(until))
	}
	return ""
}

// dsLeft: every DS the parent serves is one of the step's DS set: the leaving
// provider's is gone. With the set not known it cannot be told, and the step
// waits, as the syncher leaves the parent's DS alone then. A test stands in.
var dsLeft = func(conf *Config, zone string, seen parentSeen) bool {
	return dsAllIntended(seen.dsRRs, func(digest uint8) ([]dns.RR, bool) {
		intent, err := conf.computedDSIntent(zone, digest)
		return intent.Set, err == nil && intent.Known
	})
}

// dsAllIntended: every DS served is one of the set, as intended gives it for the
// DS's digest type, and compared whole: two providers' keys can share a tag and
// an algorithm, and a parent may compute its own of any type. A digest type none
// is computed for here goes by its tag and algorithm, against the SHA-256 set:
// it may be served for a key that stays, and nothing would ever end that wait.
func dsAllIntended(served []*dns.DS, intended func(digest uint8) ([]dns.RR, bool)) bool {
	for _, ds := range served {
		set, known := intended(ds.DigestType)
		whole := len(set) > 0
		if known && !whole {
			set, known = intended(dns.SHA256)
		}
		if !known || !slices.ContainsFunc(set, func(rr dns.RR) bool {
			want, ok := rr.(*dns.DS)
			return ok && want.KeyTag == ds.KeyTag && want.Algorithm == ds.Algorithm &&
				(!whole || strings.EqualFold(want.Digest, ds.Digest)) // not-a-name: a digest in hex
		}) {
			return false
		}
	}
	return true
}

// removalWaitSaid logs what a step waits until, once for each thing.
func removalWaitSaid(conf *Config, zone, id, step, until string) string {
	if conf.InternalMp.reconciles.sayOnce(canonicalName(zone), "removal "+id+" "+until) {
		logRemovalStep(zone, id, step, until)
	}
	return until
}

func removalTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") + " UTC" }

// --- A parent that does not move ---

// refusalWarnEvery is how often a watch on a parent that refuses the zone's key
// warns, past leaving-timeout.
const refusalWarnEvery = time.Hour

// watches notes the step held that watches the parent, "" for none.
func (b *reconcileBook) watches(zone, step string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.zone(zone).watching = step
}

// parentRefusalNote is what a watch on the parent adds to the step's status
// while the parent refuses the zone's key: no UPDATE goes (design 6), so the
// parent moves by another route or the leader's operator gives the word. Past
// leaving-timeout it also warns, once an hour. "" with the key not refused.
func (conf *Config) parentRefusalNote(zone, id, step string) string {
	rb := &conf.InternalMp.reconciles
	key := canonicalName(zone)
	wait := "refused " + step
	keyid, state, refused := conf.parentRefusesKey(ZoneName(zone))
	if !refused {
		rb.forgetWait(key, wait)
		return ""
	}
	now := time.Now()
	since := rb.sinceFirst(key, wait, now)
	if now.Sub(since) >= leavingTimeoutFor(conf.MpConfig()) && rb.warnDue(key, now) {
		lg.Warn("a removal's step waits for a parent that refuses the zone's SIG(0) key: the parent must move by another route, or the leader's operator gives the word (agent parentsync go-on)",
			"zone", zone, "provider", id, "step", step, "keyid", keyid, "state", state, "since", since.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf(" (the parent refuses the zone's SIG(0) key %d (%s), so no UPDATE goes: it must move by another route, or the leader's operator gives the word: agent parentsync go-on)", keyid, state)
}

// warnDue: refusalWarnEvery has passed since the zone's last warning.
func (b *reconcileBook) warnDue(zone string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	zr := b.zone(zone)
	if now.Sub(zr.warnedAt) < refusalWarnEvery {
		return false
	}
	zr.warnedAt = now
	return true
}

// giveParentWord keeps the leader's operator's word for a step's watch, the
// zone named in any case.
func (s *InstructionStore) giveParentWord(zone, step string) error {
	s.mu.Lock()
	name, _ := s.zoneLocked(zone)
	s.mu.Unlock()
	if name == "" {
		return fmt.Errorf("zone %s: no serials kept", zone)
	}
	return s.update(name, func(z *zoneSerials) error {
		if !z.reconciling() || slices.Contains(z.ParentWords, step) {
			return errToldUnchanged
		}
		z.ParentWords = append(z.ParentWords, step)
		return nil
	})
}

// parentWord: the leader's operator gave the word for the step's watch, the
// zone named in any case.
func (s *InstructionStore) parentWord(zone, step string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, z := s.zoneLocked(zone)
	return z != nil && slices.Contains(z.ParentWords, step)
}

// goOnPastParent is the word of the operator of this agent, the zone's leader
// (agent parentsync go-on, decision 110): the step held, which watches a parent
// that does not move, stops watching it. What follows the watch runs as ever,
// its TTLs counted from now. Refused unless a step here watches the parent.
func (conf *Config) goOnPastParent(zone string) (string, error) {
	rb := &conf.InternalMp.reconciles
	key := canonicalName(zone)
	rb.mu.Lock()
	step := rb.zone(key).watching
	rb.mu.Unlock()
	if step == "" {
		return "", fmt.Errorf("no removal's step here watches the parent of zone %s", zone)
	}
	if err := conf.InternalMp.Instructions.giveParentWord(zone, step); err != nil && !errors.Is(err, errToldUnchanged) {
		return "", fmt.Errorf("zone %s: the word for step %q could not be kept: %w", zone, step, err)
	}
	rb.watches(key, "")
	seen, _ := conf.parentNow(zone)
	lg.Warn("the leader's operator gave the word: a removal's step no longer watches the parent", "zone", zone, "step", step, "parent_ns", seen.ns, "parent_ds", seen.ds)
	conf.askThaw(zone)
	return fmt.Sprintf("Zone %s: step %q no longer watches the parent, which may still hold what leaves; its TTLs are counted from now", zone, step), nil
}

// safeToRemoveSaid is the status's "safe to remove", with this provider's NS
// names the parent still serves, as far as it has been read: the word of the
// leader's operator may have gone on past them.
func (conf *Config) safeToRemoveSaid(zone string) string {
	seen, ok := conf.parentNow(zone)
	if !ok {
		return "safe to remove (what the parent names has not been read yet)"
	}
	var named []string
	if mp := conf.MpConfig(); mp != nil {
		for _, n := range mp.Local.Nameservers {
			if slices.Contains(seen.ns, canonicalName(n)) {
				named = append(named, n)
			}
		}
	}
	if len(named) > 0 {
		return "safe to remove, though the parent still names " + strings.Join(named, ", ")
	}
	return "safe to remove"
}

// --- Other readers ---

// stillConfirmsKeys: id is among the zone's KeyConfirmers at its step: a
// leaving provider until its NS TTL has passed. Resolvers sent to it need
// another signer's new DNSKEY, so that distribution has no time-out for it
// (design 5.2).
func stillConfirmsKeys(zone ZoneName, id AgentId) bool {
	return isAmong(identities(rolesForZone(zone).KeyConfirmers), id)
}

// lookAgainAtDnskeyWaits has the zone's DNSKEY distributions look again at who
// they wait for: a step took a provider out of the key confirmers, and a
// rollover paused on it resumes (design 5.2).
func (conf *Config) lookAgainAtDnskeyWaits(zone ZoneName) {
	if tm := conf.InternalMp.MPTransport; tm != nil {
		tm.lookAgainAtDnskeyPropagations(zone)
	}
}

// safeToRemove: this agent no longer has a role in the zone, the transition
// that took its last role away is done, and nothing is under way: its operator
// may take the zone away (design 5.2). So too when the last thaw took its
// record: a leader thaws only after "done", and the thaw's own transition is
// done here.
func (conf *Config) safeToRemove(zone string) bool {
	mp := conf.MpConfig()
	if mp == nil {
		return false
	}
	s := conf.InternalMp.Instructions
	in, ok := s.reconcileInputs(zone)
	if !ok || !in.enforced || in.reconciling {
		return false
	}
	from := s.lastFromReading(zone)
	switch zoneStanding(in.active.Reading, mp.Identity) {
	case standingNoRole:
		// votesIn would say yes with no thaw kept, and of a zone with no records
		return from != nil && zoneStanding(from, mp.Identity) == standingVoting
	case standingNone:
		return from != nil && zoneStanding(from, mp.Identity) != standingNone
	}
	return false
}

// recordGone: safeToRemove because the last thaw took this agent's record. It
// has no part in what the others agree on next.
func (conf *Config) recordGone(zone string) bool {
	mp := conf.MpConfig()
	return mp != nil && conf.safeToRemove(zone) && zoneStanding(conf.InternalMp.Instructions.activeReading(zone), mp.Identity) == standingNone
}
