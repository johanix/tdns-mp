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
// HSYNCPARAM marks as signers. Unknown while any of them has not spoken, or
// has a SEP key whose ds is undecided, or names a ds=1 key this agent holds
// no record of; the syncher then leaves the parent's DS alone (Q9). A
// provider that has spoken and listed no keys has an empty share. This
// provider's own share, when it signs the zone, is its signer's latest
// inventory, since a signer never distributes to its own agent. As with the
// owner's answer from the inventory, a set with no SEP key in it is not an
// answer: nobody has said anything about a key.
func (conf *Config) computedDSIntent(zone string, digest uint8) (tdns.DSIntent, error) {
	zone = dns.Fqdn(zone)
	mpzd, ok := Zones.Get(zone)
	if !ok || mpzd == nil {
		return tdns.DSIntent{}, nil
	}
	hp := mpzd.getHSYNCPARAM()
	if hp == nil {
		return tdns.DSIntent{}, nil
	}
	signers := hp.GetSigners()
	if len(signers) == 0 {
		lgEngine.Debug("computed DS set: the zone names no signing provider; nothing to compute", "zone", zone)
		return tdns.DSIntent{}, nil
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

	var set []dns.RR
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
				lgEngine.Debug("computed DS set: our own signer signs the zone and has sent no inventory; the set is unknown", "zone", zone)
				return tdns.DSIntent{}, nil
			}
			for _, it := range snap.Inventory {
				if it.Flags&dns.SEP == 0 {
					continue
				}
				seen = true
				if it.DS == nil {
					return tdns.DSIntent{}, nil
				}
				if !*it.DS {
					continue
				}
				rr, err := dns.NewRR(it.KeyRR)
				if err != nil {
					return tdns.DSIntent{}, fmt.Errorf("computed DS set: key %d of %s: %w", it.KeyTag, zone, err)
				}
				if dk, ok := rr.(*dns.DNSKEY); ok {
					addDS(dk)
				}
			}
			continue
		}
		share, spoke := byLabel[s]
		if !spoke {
			lgEngine.Debug("computed DS set: a signing provider has not said what it holds its keys as; the set is unknown", "zone", zone, "provider", s)
			return tdns.DSIntent{}, nil
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
				// be made into a DS, and with ds=1 that leaves the set unknown
				if st.DS != nil && *st.DS && !dnskeyRecordKnown(share.dnskeys, st.KeyTag) {
					lgEngine.Debug("computed DS set: a provider says ds=1 for a key it sent no record of; the set is unknown", "zone", zone, "provider", s, "keytag", st.KeyTag)
					return tdns.DSIntent{}, nil
				}
				continue
			}
			seen = true
			if st.DS == nil {
				return tdns.DSIntent{}, nil
			}
			if !*st.DS {
				continue
			}
			for _, dk := range keys {
				addDS(dk)
			}
		}
	}
	return tdns.DSIntent{Set: set, Known: seen}, nil
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
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		return
	}
	before := conf.computedDSIntentOr(string(zone))
	tm.NoteForeignKeyStates(zone, from, ops)
	conf.noteComputedDSSet(ctx, string(zone), before)
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
