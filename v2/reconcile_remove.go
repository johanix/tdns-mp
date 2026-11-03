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
 *     nsmgmt=agent, the leader syncs and watches the parent until its NS
 *     RRset no longer names the names, and counts the NS TTL from then. Then
 *     it leaves KeyConfirmers.
 *  3. If it leaves signers=: DSSigners drop it, its CDS is withdrawn, the
 *     leader syncs and watches the parent until its DS is gone, and waits the
 *     DS and DNSKEY TTLs from then.
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
	"context"
	"fmt"
	"net"
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
	// dnskeyLookWait is how long a look at the zone's DNSKEY TTL waits for each
	// of its servers.
	dnskeyLookWait = 2 * time.Second
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
				return conf.removalDSWait(zone, id)
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

// parentSeen is what the parent serves for the zone, as last looked at, and
// the TTL the zone's own servers give its DNSKEY RRset.
type parentSeen struct {
	at        time.Time
	ns        []string // the names of its NS RRset, folded
	nsTTL     uint32
	nsServer  string   // the parent's server that said so
	ds        []uint16 // the key tags of its DS RRset
	dsTTL     uint32   // as last served
	dnskeyTTL uint32   // the largest seen since the zone's first look; 0 if none
}

// parentLook asks the parent what it serves for the zone; a test stands in
// for it. It asks the servers AnalyseZoneDelegation asks, in the same order.
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
	var last error
	for _, server := range zd.ParentServers {
		nsrrs, err := tdns.AuthQuery(zd.ZoneName, server, dns.TypeNS)
		if err != nil {
			last = err
			continue
		}
		if len(nsrrs) == 0 {
			continue
		}
		dsrrs, err := tdns.AuthQuery(zd.ZoneName, server, dns.TypeDS)
		if err != nil {
			last = err
			continue
		}
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
				seen.dsTTL = max(seen.dsTTL, ds.Hdr.Ttl)
			}
		}
		// the servers the parent names, and those the zone itself names
		zoneNames, _ := zoneNSOf(zone)
		names := append(slices.Clone(seen.ns), zoneNames...)
		slices.Sort(names)
		seen.dnskeyTTL = servedDnskeyTTL(zd.ZoneName, serverAddrs(conf.Config.Internal.ImrEngine, slices.Compact(names)))
		return seen, nil
	}
	if last == nil {
		last = fmt.Errorf("no parent server gave an NS RRset for %s", zd.ZoneName)
	}
	return parentSeen{}, last
}

// serverAddrs are the addresses of the named servers, found as FetchParentData
// finds the parent's. A name that does not resolve gives none.
func serverAddrs(imr *tdns.Imr, names []string) []string {
	var addrs []string
	for _, name := range names {
		for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			resp, err := imr.ImrQuery(context.Background(), name, rrtype, dns.ClassINET, nil)
			if err != nil || resp == nil || resp.RRset == nil {
				continue
			}
			for _, rr := range resp.RRset.RRs {
				switch rr := rr.(type) {
				case *dns.A:
					addrs = append(addrs, net.JoinHostPort(rr.A.String(), "53"))
				case *dns.AAAA:
					addrs = append(addrs, net.JoinHostPort(rr.AAAA.String(), "53"))
				}
			}
		}
	}
	return addrs
}

// servedDnskeyTTL is the largest TTL the servers give the zone's DNSKEY RRset,
// 0 when none tells. Providers' signer policies may differ, and a resolver may
// hold the RRset of any of them. Over TCP: the RRset of a zone with several
// signers does not fit a plain UDP answer.
func servedDnskeyTTL(zone string, servers []string) uint32 {
	c := &dns.Client{Net: "tcp", Timeout: dnskeyLookWait}
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeDNSKEY)
	var ttl uint32
	for _, server := range servers {
		res, _, err := c.Exchange(m, server)
		if err != nil || res.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range res.Answer {
			if key, ok := rr.(*dns.DNSKEY); ok {
				ttl = max(ttl, key.Hdr.Ttl)
			}
		}
	}
	return ttl
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
				// a server the parent has since dropped may have served the larger
				got.dnskeyTTL = max(got.dnskeyTTL, zr.parent.dnskeyTTL)
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
		zr.stepSync, zr.syncAt = false, time.Time{}
	}
}

// --- The waits ---

// removalNSWait is what the leaving provider's NS step waits for: under
// nsmgmt=agent the withdrawal's confirmations; then until the parent's NS
// RRset no longer names the stored names, and from then the larger of the
// parent's and the zone's NS TTL, plus the propagation delay. "" once passed.
func (conf *Config) removalNSWait(zone, label, id string, agentNS bool) string {
	if agentNS && !conf.removalWithdrawn(zone, id, "NS") {
		return "for the withdrawal of its NS to be confirmed"
	}
	seen, ok := conf.parentNow(zone)
	if !ok {
		conf.askStepSync(zone, "a removal's NS step")
		return "until the parent's NS RRset is known"
	}
	rb := &conf.InternalMp.reconciles
	key := canonicalName(zone)
	wait := "ns " + label
	rm, _ := conf.InternalMp.Instructions.removal(zone, label, "")
	var named []string
	for _, n := range rm.NSNames {
		if slices.Contains(seen.ns, canonicalName(n)) {
			named = append(named, n)
		}
	}
	zoneNames, zoneTTL := zoneNSOf(zone)
	if len(named) > 0 {
		conf.askStepSync(zone, "a removal's NS step")
		rb.forgetWait(key, wait)
		text := "until the parent no longer names " + strings.Join(named, ", ")
		if !agentNS && slices.ContainsFunc(named, func(n string) bool { return slices.Contains(zoneNames, canonicalName(n)) }) {
			text += " (the owner's NS RRset still names it)"
		}
		return removalWaitSaid(conf, zone, id, "2 (its NS)", text)
	}
	delay, largest := conf.delegationNotifyWait(zone)
	since := rb.sinceFirst(key, wait, time.Now())
	until := since.Add(time.Duration(max(seen.nsTTL, zoneTTL))*time.Second + delay)
	// the wait's terms as they are read, and again if one of them changes
	if rb.sayOnce(key, fmt.Sprintf("%s terms %d %s %d %s %s", wait, seen.nsTTL, seen.nsServer, zoneTTL, delay, since)) {
		lg.Info("a removal's NS step counts its wait", "zone", zone, "provider", id, "parent_ns_ttl", seen.nsTTL, "parent_server", seen.nsServer,
			"zone_ns_ttl", zoneTTL, "delay", delay, "delay_from", largest, "since", since.UTC().Format(time.RFC3339), "until", until.UTC().Format(time.RFC3339))
	}
	if time.Now().Before(until) {
		return removalWaitSaid(conf, zone, id, "2 (its NS)", "for the NS TTL until "+removalTime(until))
	}
	return ""
}

// removalDSWait is what the leaving provider's DS step waits for: its CDS
// withdrawn, then until the parent no longer serves its DS, and from then the
// parent's DS TTL, as last served, and the DNSKEY TTL. "" once passed.
func (conf *Config) removalDSWait(zone, id string) string {
	if !conf.removalWithdrawn(zone, id, "CDS") {
		return "for the withdrawal of its CDS to be confirmed"
	}
	seen, ok := conf.parentNow(zone)
	if !ok {
		conf.askStepSync(zone, "a removal's DS step")
		return "until the parent's DS RRset is known"
	}
	rb := &conf.InternalMp.reconciles
	key := canonicalName(zone)
	wait := "ds " + id
	if !dsLeft(conf, zone, seen) {
		conf.askStepSync(zone, "a removal's DS step")
		rb.forgetWait(key, wait)
		return removalWaitSaid(conf, zone, id, "3 (its DS)", "until the parent no longer serves its DS")
	}
	ttl := removalTTLUnknown
	if seen.dsTTL != 0 {
		ttl = time.Duration(seen.dsTTL) * time.Second
	}
	until := rb.sinceFirst(key, wait, time.Now()).Add(max(ttl, conf.dnskeyTTLOf(zone, id, seen)))
	if time.Now().Before(until) {
		return removalWaitSaid(conf, zone, id, "3 (its DS)", "for the DS and DNSKEY TTLs until "+removalTime(until))
	}
	return ""
}

// dsLeft: every DS the parent serves is one of the step's DS set: the leaving
// provider's is gone. With the set not known it cannot be told, and the step
// waits, as the syncher leaves the parent's DS alone then. A test stands in.
var dsLeft = func(conf *Config, zone string, seen parentSeen) bool {
	if len(seen.ds) == 0 {
		return true
	}
	intent, err := conf.computedDSIntent(zone, dns.SHA256)
	if err != nil || !intent.Known {
		return false
	}
	tags := map[uint16]bool{}
	for _, rr := range intent.Set {
		if ds, ok := rr.(*dns.DS); ok {
			tags[ds.KeyTag] = true
		}
	}
	return !slices.ContainsFunc(seen.ds, func(tag uint16) bool { return !tags[tag] })
}

// dnskeyTTLOf is the DNSKEY TTL of the zone: what its servers were seen to
// serve. Failing that, the larger of the zone's own RRset's and the leaving
// provider's contribution's, removalTTLUnknown when this agent holds neither.
// That fallback errs long: a held key has its TTL as generated (3600), not the
// one its signer's policy serves it with.
func (conf *Config) dnskeyTTLOf(zone, id string, seen parentSeen) time.Duration {
	if seen.dnskeyTTL != 0 {
		return time.Duration(seen.dnskeyTTL) * time.Second
	}
	if conf.InternalMp.reconciles.sayOnce(canonicalName(zone), "served dnskey ttl") {
		lg.Warn("no server told the zone's DNSKEY TTL; a removal goes by the TTL held here", "zone", zone, "provider", id)
	}
	var ttl uint32
	if mpzd, ok := Zones.Get(zone); ok && mpzd != nil && mpzd.ZoneData != nil {
		if apex, err := mpzd.GetOwner(mpzd.ZoneName); err == nil && apex != nil {
			for _, rr := range apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs {
				ttl = max(ttl, rr.Header().Ttl)
			}
		}
	}
	if zdr := conf.InternalMp.ZoneDataRepo; zdr != nil {
		for _, rr := range zdr.heldOf(ZoneName(zone), AgentId(id), dns.TypeDNSKEY) {
			ttl = max(ttl, rr.Header().Ttl)
		}
	}
	if ttl == 0 {
		return removalTTLUnknown
	}
	return time.Duration(ttl) * time.Second
}

// removalWaitSaid logs what a step waits until, once for each thing.
func removalWaitSaid(conf *Config, zone, id, step, until string) string {
	if conf.InternalMp.reconciles.sayOnce(canonicalName(zone), "removal "+id+" "+until) {
		logRemovalStep(zone, id, step, until)
	}
	return until
}

func removalTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") + " UTC" }

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
		return votesIn(from, AgentId(mp.Identity))
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
