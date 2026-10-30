/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The DS set of a zone the leader's own signer does not own (key lifecycle
 * ownership design, Amendment 2; §6 row S5d, first slice). A parentsync=agent
 * zone elects its leader among every provider that serves it, and a provider
 * may serve a zone without signing it. Such a leader's signer sends no
 * inventory marked Owned, so nothing here knew the zone's DS set, and the
 * sync an election asked for found nothing to say. The agent computes the
 * set instead, from what the signing providers said about their keys in the
 * DNSKEY distributions it already receives (tdns-mp #58), and the DNSKEY
 * records those distributions carried.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"sort"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// foreignShare is one provider's word about the zone's keys: the key states
// of its latest distribution, and the DNSKEY records its distributions
// carried. A provider with an entry has spoken, whatever it listed.
type foreignShare struct {
	states  []core.KeyState
	dnskeys []*dns.DNSKEY
}

// applyDnskeyRecords is what one DNSKEY operation does to the records kept
// for its sender: a replace is the sender's whole set, an add and a delete
// edit it. Records that do not parse as DNSKEYs are left out.
func applyDnskeyRecords(cur []*dns.DNSKEY, op core.RROperation) []*dns.DNSKEY {
	var parsed []*dns.DNSKEY
	for _, s := range op.Records {
		rr, err := dns.NewRR(s)
		if err != nil {
			continue
		}
		if dk, ok := rr.(*dns.DNSKEY); ok {
			parsed = append(parsed, dk)
		}
	}
	has := func(set []*dns.DNSKEY, dk *dns.DNSKEY) bool {
		for _, c := range set {
			if dns.IsDuplicate(c, dk) {
				return true
			}
		}
		return false
	}
	switch op.Operation {
	case "replace":
		return parsed
	case "add":
		out := append([]*dns.DNSKEY(nil), cur...)
		for _, dk := range parsed {
			if !has(out, dk) {
				out = append(out, dk)
			}
		}
		return out
	case "delete":
		var out []*dns.DNSKEY
		for _, c := range cur {
			if !has(parsed, c) {
				out = append(out, c)
			}
		}
		return out
	}
	return cur
}

// foreignSharesFor is a copy of what every other provider's agent has said
// about the zone's keys, by sending agent.
func (tm *MPTransportBridge) foreignSharesFor(zone ZoneName) map[AgentId]foreignShare {
	tm.foreignKeyStatesMu.Lock()
	defer tm.foreignKeyStatesMu.Unlock()
	out := map[AgentId]foreignShare{}
	for a, st := range tm.foreignKeyStates[zone] {
		out[a] = foreignShare{
			states:  append([]core.KeyState(nil), st...),
			dnskeys: append([]*dns.DNSKEY(nil), tm.foreignDnskeys[zone][a]...),
		}
	}
	return out
}

// computedDSIntent is the DS set of zone from what its signing providers
// said (Amendment 2, A2.2): every SEP key among their keys whose provider
// says ds=1, as DS records of the given digest type; a key its provider
// says ds=0 for is left out. The signing providers are the ones the zone's
// HSYNCPARAM marks as signers, and those leaving it while their HSYNC3
// records stay (the signing set, #147). Unknown while any of them has not spoken, or
// has a SEP key whose ds is undecided, or names a ds=1 key this agent holds
// no record of; the syncher then leaves the parent's DS alone (Q9). A
// provider that has spoken and listed no keys has an empty share (A2.2's
// empty-share clause, S7): it is present with nothing in it, so it holds
// nothing back, and the set is known when every other signing provider has
// spoken. Spoken is an entry in the agent's bookkeeping, which an explicit
// empty list makes, and so does a replace of the whole set by no record
// from a provider heard from before (NoteForeignKeyStates); a provider that
// never said has none. This provider's own share, when it signs the zone,
// is its signer's latest inventory, since a signer never distributes to its
// own agent; an inventory marked not signing is an empty share. As with the owner's answer from the inventory, a set with no
// SEP key in it is not an answer: nobody has said anything about a key.
func (conf *Config) computedDSIntent(zone string, digest uint8) (tdns.DSIntent, error) {
	in, _, err := conf.computedDSSet(zone, digest)
	return in, err
}

// dsWait is one thing a DS set that is not known waits for: a provider, by
// its identity (its label where the zone's records name none), why, and the
// key the reason is about, where it is about one.
type dsWait struct {
	provider string
	why      string
	keytag   uint16
}

// Why a DS set waits for a provider.
const (
	dsWaitNotSpoken   = "not spoken"   // a provider in signers= has said nothing about its keys
	dsWaitUndecided   = "ds undecided" // a SEP key whose ds is not set
	dsWaitNoRecord    = "no record"    // a key with ds=1 or undecided whose DNSKEY record this agent does not hold
	dsWaitNoInventory = "no inventory" // this provider's own signer has sent none
)

func (w dsWait) String() string {
	if w.keytag != 0 {
		return fmt.Sprintf("%s (%s, key %d)", w.provider, w.why, w.keytag)
	}
	return fmt.Sprintf("%s (%s)", w.provider, w.why)
}

// computedDSWaitingFor names whom the zone's computed DS set waits for, and
// why, in every case in which computedDSIntent finds the set unknown for a
// zone that names a signer. An error is computedDSIntent's. None is named
// when the set is known, and when every signing provider has spoken and
// none holds a key with the SEP flag: then there is nobody to name.
func (conf *Config) computedDSWaitingFor(zone string) ([]dsWait, error) {
	_, waits, err := conf.computedDSSet(zone, dns.SHA256)
	return waits, err
}

// computedDSSet is computedDSIntent, with whom an unknown set waits for.
// Every case that makes the set unknown names a provider.
func (conf *Config) computedDSSet(zone string, digest uint8) (tdns.DSIntent, []dsWait, error) {
	zone = dns.Fqdn(zone)
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return tdns.DSIntent{}, nil, nil
	}
	if in := mpzd.instructions(); in == nil || !in.HasParam {
		return tdns.DSIntent{}, nil, nil
	}
	// The signing set, not signers= alone: a provider leaving signers=
	// signs on until the owner removes its HSYNC3 record, and its DS stays
	// in the set while it does (#147, #200 item 4).
	signers := mpzd.signingLabels()
	if len(signers) == 0 {
		lgEngine.Debug("computed DS set: the zone names no signing provider; nothing to compute", "zone", zone)
		return tdns.DSIntent{}, nil, nil
	}

	var shares map[AgentId]foreignShare
	if tm := conf.InternalMp.MPTransport; tm != nil {
		shares = tm.foreignSharesFor(ZoneName(zone))
	}
	agents := make([]string, 0, len(shares))
	for a := range shares {
		agents = append(agents, string(a))
	}
	sort.Strings(agents)
	byLabel := map[string]foreignShare{}
	for _, a := range agents {
		matched, label, err := mpzd.matchHsyncIdentity([]string{dns.Fqdn(a)})
		if err != nil || !matched {
			continue
		}
		byLabel[strings.TrimSuffix(label, ".")] = shares[AgentId(a)]
	}
	ourLabel := ""
	if matched, label, err := mpzd.matchHsyncIdentity(ourHsyncIdentities(conf.MpConfig())); err == nil && matched {
		ourLabel = strings.TrimSuffix(label, ".")
	}
	identities := mpzd.identitiesByLabel()
	identity := func(label string) string {
		if id := identities[normalizeHSYNC3Label(label)]; id != "" {
			return id
		}
		return label
	}

	var set []dns.RR
	var waits []dsWait
	seen := false
	addDS := func(dk *dns.DNSKEY) {
		ds := dk.ToDS(digest)
		if ds == nil {
			return
		}
		ds.Hdr.Name = zone
		set = append(set, ds)
	}
	for _, s := range signers {
		s = strings.TrimSuffix(s, ".")
		if s != "" && s == ourLabel {
			// our own provider signs the zone: its share is our signer's word
			var snap *KeyInventorySnapshot
			if o := conf.InternalMp.KeyLifecycleOwner; o != nil {
				snap = o.inventoryOf(zone)
			}
			if snap == nil {
				waits = append(waits, dsWait{provider: identity(s), why: dsWaitNoInventory})
				continue
			}
			if snap.NotSigning {
				continue // its keys are no DS set's source (plan S11): an empty share
			}
			for _, it := range snap.Inventory {
				if it.Flags&dns.SEP == 0 {
					continue
				}
				seen = true
				if it.DS == nil {
					waits = append(waits, dsWait{provider: identity(s), why: dsWaitUndecided, keytag: it.KeyTag})
					continue
				}
				if !*it.DS {
					continue
				}
				rr, err := dns.NewRR(it.KeyRR)
				if err != nil {
					if len(waits) > 0 {
						continue // the set is unknown before this key is read
					}
					return tdns.DSIntent{}, nil, fmt.Errorf("computed DS set: key %d of %s: %w", it.KeyTag, zone, err)
				}
				if dk, ok := rr.(*dns.DNSKEY); ok {
					addDS(dk)
				}
			}
			continue
		}
		share, spoke := byLabel[s]
		if !spoke {
			waits = append(waits, dsWait{provider: identity(s), why: dsWaitNotSpoken})
			continue
		}
		for _, st := range share.states {
			var keys []*dns.DNSKEY
			for _, dk := range share.dnskeys {
				if dk.KeyTag() == st.KeyTag && dk.Flags&dns.SEP != 0 {
					keys = append(keys, dk)
				}
			}
			if len(keys) == 0 {
				// a ZSK, or a key we hold no record of: the latter cannot
				// be made into a DS, so with ds=1 the set is unknown, and
				// with ds undecided too (it may be a SEP key whose record
				// has not arrived; only ds=0 is nothing to make a DS of)
				if (st.DS == nil || *st.DS) && !dnskeyRecordKnown(share.dnskeys, st.KeyTag) {
					waits = append(waits, dsWait{provider: identity(s), why: dsWaitNoRecord, keytag: st.KeyTag})
				}
				continue
			}
			seen = true
			if st.DS == nil {
				waits = append(waits, dsWait{provider: identity(s), why: dsWaitUndecided, keytag: st.KeyTag})
				continue
			}
			if !*st.DS {
				continue
			}
			for _, dk := range keys {
				addDS(dk)
			}
		}
	}
	if len(waits) > 0 {
		lgEngine.Debug("computed DS set: the set is unknown", "zone", zone, "waiting_for", dsWaitsString(waits))
		return tdns.DSIntent{}, waits, nil
	}
	return tdns.DSIntent{Set: set, Known: seen}, nil, nil
}

// dsWaitsString names the waits as one line.
func dsWaitsString(waits []dsWait) string {
	parts := make([]string, len(waits))
	for i, w := range waits {
		parts[i] = w.String()
	}
	return strings.Join(parts, ", ")
}

// foreignDSWithheld is the agent's check on the DS set its own signer's
// inventory gives (MPKeyLifecycleOwner.DSIntent): another provider's DS
// leaves the parent only when the key states that provider's agent sent this
// agent, with its DNSKEY distributions, say so (tdns-mp #207). It names a key
// those key states have standby, active or retired with ds=1 (P3, as
// foreignDSFor reads the same key states at the signer, where this agent
// relays them) and that the inventory does not hold as a SEP key with ds=1;
// empty when there is none. One inventory without the key is not the key
// states dropping it: the signer may have taken a copy of the zone that
// lacked it. A provider the zone owner no longer names among the signers,
// and that is not leaving it either (#147), is not asked: its DS is the
// leader's to remove.
func (conf *Config) foreignDSWithheld(zone string, inv []tdns.KeyInventoryItem) string {
	zone = dns.Fqdn(zone)
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return ""
	}
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return ""
	}
	if in := mpzd.instructions(); in == nil || !in.HasParam {
		return ""
	}
	signing := map[string]bool{}
	for _, s := range mpzd.signingLabels() {
		signing[s] = true
	}
	ourLabel := ""
	if matched, label, err := mpzd.matchHsyncIdentity(ourHsyncIdentities(conf.MpConfig())); err == nil && matched {
		ourLabel = trimDot(label)
	}
	held := map[uint16]bool{}
	for _, it := range inv {
		if it.Flags&dns.SEP != 0 && it.DS != nil && *it.DS {
			held[it.KeyTag] = true
		}
	}
	shares := tm.foreignSharesFor(ZoneName(zone))
	agents := make([]string, 0, len(shares))
	for a := range shares {
		agents = append(agents, string(a))
	}
	sort.Strings(agents)
	for _, a := range agents {
		matched, label, err := mpzd.matchHsyncIdentity([]string{dns.Fqdn(a)})
		if err != nil || !matched {
			continue
		}
		label = trimDot(label)
		if label == ourLabel || !signing[label] {
			continue
		}
		share := shares[AgentId(a)]
		for _, st := range share.states {
			// a key whose record has not arrived is taken to be a SEP key:
			// its provider says its DS belongs at the parent
			sep := true
			for _, dk := range share.dnskeys {
				if dk.KeyTag() == st.KeyTag {
					sep = dk.Flags&dns.SEP != 0
					break
				}
			}
			want, decided := foreignDSFor(foreignSaid{Provider: label, State: st.State, DS: st.DS}, sep, signing)
			if !decided || !want || held[st.KeyTag] {
				continue
			}
			who := label
			if id := mpzd.identitiesByLabel()[label]; id != "" {
				who = id
			}
			return fmt.Sprintf("provider %s holds its key %d %s with its DS at the parent, and the signer's inventory does not have that DS",
				who, st.KeyTag, st.State)
		}
	}
	return ""
}

// dnskeyRecordKnown reports whether any record carries the key tag.
func dnskeyRecordKnown(records []*dns.DNSKEY, keytag uint16) bool {
	for _, dk := range records {
		if dk.KeyTag() == keytag {
			return true
		}
	}
	return false
}

// computedDSIntentOr is computedDSIntent with any failure as unknown, and
// unknown on every role but the agent: what a comparison before a change
// needs.
func (conf *Config) computedDSIntentOr(zone string) tdns.DSIntent {
	o := conf.InternalMp.KeyLifecycleOwner
	if o == nil || o.computedSource() == nil {
		return tdns.DSIntent{}
	}
	in, err := conf.computedDSIntent(zone, dns.SHA256)
	if err != nil {
		return tdns.DSIntent{}
	}
	return in
}

// noteForeignDistribution records what a provider's DNSKEY distribution
// says about its keys, and, for a zone this agent's own signer does not
// own, asks the leader's delegation sync when the DS set computed from it
// is known and not what it was (A2.2: the change of the set is seen where
// the key states are written). The signer's own inventory asks for the
// zone it owns (noteKeyInventory); the two never both apply to a zone.
func (conf *Config) noteForeignDistribution(ctx context.Context, zone ZoneName, from AgentId, ops []core.RROperation) {
	conf.noteForeignAnswer(ctx, zone, from, ops, false)
}

// noteForeignAnswer is noteForeignDistribution for an update that may be
// a complete answer to a request for the zone's state (complete), which
// makes its provider speak (noteForeignKeyStates).
//
// For a zone our own signer owns, the inventory gives the DS set, and the
// other providers' key states can hold it back (foreignDSWithheld). Key
// states that end the hold make the set known with nothing else changing:
// that asks for the sync, as a set that turns known does.
func (conf *Config) noteForeignAnswer(ctx context.Context, zone ZoneName, from AgentId, ops []core.RROperation, complete bool) {
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return
	}
	var owned *KeyInventorySnapshot
	if o := conf.InternalMp.KeyLifecycleOwner; o != nil {
		if snap := o.inventoryOf(string(zone)); snap != nil && snap.Owned {
			owned = snap
		}
	}
	withheld := ""
	if owned != nil {
		withheld = conf.foreignDSWithheld(string(zone), owned.Inventory)
	}
	before := conf.computedDSIntentOr(string(zone))
	tm.noteForeignKeyStates(zone, from, ops, complete)
	conf.noteComputedDSSet(ctx, string(zone), before)
	if withheld != "" && conf.foreignDSWithheld(string(zone), owned.Inventory) == "" {
		conf.requestDelegationSync(ctx, string(zone), "another provider's key states agree with the signer's inventory now: the zone's DS set is known")
	}
}

// dsSetUnknown: the zone names a signer and its DS set, as the syncher is
// given it (MPKeyLifecycleOwner.DSIntent), is unknown, and whom it waits
// for. For a zone this provider's signer owns the set is read from the
// inventory here, as DSIntent reads it, so that each status and each sync
// do not log DSIntent's warning once more; otherwise from the computed set.
func (conf *Config) dsSetUnknown(ds tdns.DelegationSyncRequest) (waitingFor string, unknown bool) {
	o := conf.InternalMp.KeyLifecycleOwner
	if o == nil || ds.ZoneData == nil || !ds.ZoneData.Options[tdns.OptMultiProvider] {
		return "", false
	}
	mpzd, ok := Zones.Get(ds.ZoneName)
	if !ok || mpzd == nil {
		return "", false
	}
	if len(mpzd.roles().DSSigners) == 0 {
		return "", false
	}
	if snap := o.inventoryOf(ds.ZoneName); snap != nil && snap.Owned {
		return conf.ownedDSWaitingFor(o, ds.ZoneName, snap)
	}
	in, err := o.DSIntent(ds.ZoneData, dns.SHA256)
	if err != nil {
		return fmt.Sprintf("nobody: the DS set could not be read: %v", err), true
	}
	if in.Known {
		return "", false
	}
	return conf.dsSetWaitingFor(ds.ZoneName), true
}

// ownedDSWaitingFor is dsSetUnknown for a zone this provider's signer owns,
// read as DSIntent reads it: another provider whose key states hold the set
// back (foreignDSWithheld), this provider's SEP keys whose ds is not set,
// or an inventory with no SEP key.
func (conf *Config) ownedDSWaitingFor(o *MPKeyLifecycleOwner, zone string, snap *KeyInventorySnapshot) (string, bool) {
	if check := o.foreignDSCheck(); check != nil {
		if why := check(zone, snap.Inventory); why != "" {
			return why, true
		}
	}
	self := ""
	if mp := conf.MpConfig(); mp != nil {
		self = dns.Fqdn(mp.Identity)
	}
	var waits []dsWait
	sep := false
	for _, it := range snap.Inventory {
		if it.Flags&dns.SEP == 0 {
			continue
		}
		sep = true
		if it.DS == nil {
			waits = append(waits, dsWait{provider: self, why: dsWaitUndecided, keytag: it.KeyTag})
		}
	}
	switch {
	case !sep:
		return "nobody: the signer's inventory holds no key with the SEP flag", true
	case len(waits) > 0:
		return dsWaitsString(waits), true
	}
	return "", false
}

// dsSetWaitingFor names whom the zone's unknown DS set waits for, and why:
// for a zone this provider's signer owns as ownedDSWaitingFor has it,
// otherwise the computed set's waits.
func (conf *Config) dsSetWaitingFor(zone string) string {
	zone = dns.Fqdn(zone)
	if o := conf.InternalMp.KeyLifecycleOwner; o != nil {
		if snap := o.inventoryOf(zone); snap != nil && snap.Owned {
			if why, unknown := conf.ownedDSWaitingFor(o, zone, snap); unknown {
				return why
			}
			return "nobody: the set is known"
		}
	}
	waits, err := conf.computedDSWaitingFor(zone)
	if err != nil {
		return fmt.Sprintf("nobody: the DS set could not be read: %v", err)
	}
	if len(waits) == 0 {
		return "nobody: every signing provider has spoken, and none holds a key with the SEP flag"
	}
	return dsWaitsString(waits)
}

// noteComputedDSSet asks for a sync when the computed DS set is known and
// differs from before. Nothing on a role that does not compute, and nothing
// for a zone our own signer owns: there the inventory is the source.
func (conf *Config) noteComputedDSSet(ctx context.Context, zone string, before tdns.DSIntent) {
	o := conf.InternalMp.KeyLifecycleOwner
	if o == nil || o.computedSource() == nil {
		return
	}
	if snap := o.inventoryOf(zone); snap != nil && snap.Owned {
		return
	}
	after, err := conf.computedDSIntent(zone, dns.SHA256)
	if err != nil {
		lgEngine.Warn("the computed DS set could not be read", "zone", zone, "err", err)
		return
	}
	if after.Known && !sameDSIntent(before, after) {
		conf.requestDelegationSync(ctx, dns.Fqdn(zone), "the zone's DS set changed (computed from the signing providers' key states)")
	}
}

// dsSetLine is the DS set for agent parentsync status: "known", or
// "unknown, waiting for" whom, for a zone that names a signer; empty for
// one that names none.
func (conf *Config) dsSetLine(zd *tdns.ZoneData) string {
	if zd == nil || conf.InternalMp.KeyLifecycleOwner == nil {
		return ""
	}
	mpzd, ok := Zones.Get(zd.ZoneName)
	if !ok || mpzd == nil {
		return ""
	}
	if len(mpzd.roles().DSSigners) == 0 {
		return ""
	}
	if waiting, unknown := conf.dsSetUnknown(tdns.DelegationSyncRequest{ZoneName: zd.ZoneName, ZoneData: zd}); unknown {
		return "unknown, waiting for " + waiting
	}
	return "known"
}

// identitiesByLabel maps the labels of the zone's providers to their
// identities through the step's sets, and through the signing set for a
// provider leaving it, which keeps the identity it had (#147), so that a
// provider the DS set names by its label is named by its identity.
func (mpzd *MPZoneData) identitiesByLabel() map[string]string {
	out := map[string]string{}
	r := mpzd.roles()
	for _, set := range [][]Provider{r.Servers, r.KeySigners, r.DSSigners, r.KeyConfirmers, r.Signing} {
		for _, p := range set {
			if p.Identity != "" {
				out[p.Label] = p.Identity
			}
		}
	}
	for label, id := range mpzd.signingSet() {
		if _, named := out[label]; !named && id != "" {
			out[label] = id
		}
	}
	return out
}
