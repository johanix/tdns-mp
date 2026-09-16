/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * tdns-mp as the key lifecycle owner of the multi-provider zones it has
 * taken over (design §3.5, S2's seam): registered before tdns's MainInit,
 * it answers Owns per zone -- the per-zone rollout -- names its
 * replacement commands for the tdns verbs tdns refuses on an owned zone,
 * and answers the DS intent of an owned zone from the key columns.
 */
package tdnsmp

import (
	"fmt"
	"sync"

	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// MPKeyLifecycleOwner is tdns-mp's answer to tdns.KeyLifecycleOwner.
type MPKeyLifecycleOwner struct {
	mu    sync.RWMutex
	owned map[string]bool
	keyDB func() *tdns.KeyDB
}

// NewMPKeyLifecycleOwner: keyDB is looked up at call time, since the
// keystore does not exist when the owner registers.
func NewMPKeyLifecycleOwner(keyDB func() *tdns.KeyDB) *MPKeyLifecycleOwner {
	return &MPKeyLifecycleOwner{owned: map[string]bool{}, keyDB: keyDB}
}

func (o *MPKeyLifecycleOwner) Name() string { return "tdns-mp" }

// Take makes the owner run zone's key lifecycle from now on; Release hands
// it back to tdns's hooks. This is the per-zone rollout of S3.
func (o *MPKeyLifecycleOwner) Take(zone string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.owned[dns.Fqdn(zone)] = true
}

func (o *MPKeyLifecycleOwner) Release(zone string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.owned, dns.Fqdn(zone))
}

// Zones lists the zones the owner runs.
func (o *MPKeyLifecycleOwner) Zones() []string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	var out []string
	for z := range o.owned {
		out = append(out, z)
	}
	return out
}

// Owns: taken, and a multi-provider zone (tdns asks the same; a zone that
// is not one keeps tdns's machine, whatever the configuration says).
func (o *MPKeyLifecycleOwner) Owns(zd *tdns.ZoneData) bool {
	if zd == nil || !zd.Options[tdns.OptMultiProvider] {
		return false
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.owned[dns.Fqdn(zd.ZoneName)]
}

// Command names the tdns-mpcli command that replaces a tdns lifecycle verb
// on an owned zone (design §5.10).
func (o *MPKeyLifecycleOwner) Command(verb string) string {
	switch verb {
	case "rollover", "asap":
		return "tdns-mpcli signer key rollover"
	case "cancel":
		return "tdns-mpcli signer key rollover cancel"
	case "policy-change", "policy-set", "policy-reset":
		return "tdns-mpcli signer key policy"
	case "clear", "policy-cleanup", "reset", "unstick":
		return "tdns-mpcli signer key withdraw"
	case "setstate", "generate":
		// the store verbs still work on an owned zone when they name the
		// columns (design Q4); what they must not do is shape a row by
		// tdns's table
		return "tdns-mpcli signer keystore dnssec " + verb + " with pub, sign and ds named"
	case "alg-rollover":
		return "tdns-mpcli signer key policy (the KSK algorithm)"
	}
	return "tdns-mpcli signer key"
}

// DSIntent is the owned zone's DS set from the key columns: one DS per SEP
// row with ds=1, own and foreign alike (D4). A SEP row whose ds is unset
// makes the answer unknown: nobody has decided that key's DS yet.
func (o *MPKeyLifecycleOwner) DSIntent(zd *tdns.ZoneData, digest uint8) (tdns.DSIntent, error) {
	kdb := o.keyDB()
	if kdb == nil || zd == nil {
		return tdns.DSIntent{}, nil
	}
	inv, err := tdns.GetKeyInventory(kdb, zd.ZoneName)
	if err != nil {
		return tdns.DSIntent{}, fmt.Errorf("DSIntent: inventory of %s: %w", zd.ZoneName, err)
	}
	var set []dns.RR
	seen := false
	for _, it := range inv {
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
			return tdns.DSIntent{}, fmt.Errorf("DSIntent: key %d of %s: %w", it.KeyTag, zd.ZoneName, err)
		}
		dk, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		ds := dk.ToDS(digest)
		if ds == nil {
			continue
		}
		ds.Hdr.Name = dns.Fqdn(zd.ZoneName)
		set = append(set, ds)
	}
	return tdns.DSIntent{Set: set, Known: seen}, nil
}

// RegisterMPKeyLifecycleOwner installs the owner with tdns, owning no zone
// yet; Take moves a zone onto tdns-mp's machine.
func RegisterMPKeyLifecycleOwner(conf *Config) *MPKeyLifecycleOwner {
	o := NewMPKeyLifecycleOwner(func() *tdns.KeyDB {
		if conf == nil || conf.Config == nil {
			return nil
		}
		return conf.Config.Internal.KeyDB
	})
	tdns.RegisterKeyLifecycleOwner(o)
	return o
}
