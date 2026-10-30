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
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// MPKeyLifecycleOwner is tdns-mp's answer to tdns.KeyLifecycleOwner.
type MPKeyLifecycleOwner struct {
	mu    sync.RWMutex
	owned map[string]bool
	keyDB func() *tdns.KeyDB
	// inv is the agent's side: the signer's latest inventory per zone. A
	// zone the signer runs is owned here too, and its DS set is read from
	// the inventory rather than a keystore the agent does not have
	// (design §4.1, arrow 2).
	inv map[string]*KeyInventorySnapshot
	// computed is the agent's answer for a multi-provider zone its own
	// signer does not own: the DS set computed from the signing providers'
	// key states (design Amendment 2). nil on every other role.
	computed func(zone string, digest uint8) (tdns.DSIntent, error)
	// withheld is the agent's check on the DS set its own signer's
	// inventory gives: it names a DS that the key states another signing
	// provider's agent sent this agent put at the parent, and the inventory
	// leaves out (tdns-mp #207). nil on every other role.
	withheld func(zone string, inv []tdns.KeyInventoryItem) string
	// configured is the signer's side: the zones its config hands to the
	// machine (key-lifecycle-zones), read at every call. Such a zone is
	// owned from the signer's start, taken or not, once it has keys to
	// sign with (#191). nil on every other role.
	configured func() []string
}

// SetConfiguredZones installs the signer's key-lifecycle-zones; the
// signer's start does this, before any engine runs, no other role.
func (o *MPKeyLifecycleOwner) SetConfiguredZones(f func() []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.configured = f
}

// SetComputedDSSource installs the agent's computed DS set (Amendment 2);
// the agent's start does this, no other role.
func (o *MPKeyLifecycleOwner) SetComputedDSSource(f func(zone string, digest uint8) (tdns.DSIntent, error)) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.computed = f
}

func (o *MPKeyLifecycleOwner) computedSource() func(zone string, digest uint8) (tdns.DSIntent, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.computed
}

// SetForeignDSCheck installs the agent's check on the DS set from its own
// signer's inventory; the agent's start does this, no other role.
func (o *MPKeyLifecycleOwner) SetForeignDSCheck(f func(zone string, inv []tdns.KeyInventoryItem) string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.withheld = f
}

func (o *MPKeyLifecycleOwner) foreignDSCheck() func(zone string, inv []tdns.KeyInventoryItem) string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.withheld
}

// NewMPKeyLifecycleOwner: keyDB is looked up at call time, since the
// keystore does not exist when the owner registers.
func NewMPKeyLifecycleOwner(keyDB func() *tdns.KeyDB) *MPKeyLifecycleOwner {
	return &MPKeyLifecycleOwner{owned: map[string]bool{}, keyDB: keyDB, inv: map[string]*KeyInventorySnapshot{}}
}

// SetInventory records the signer's latest inventory for a zone on the
// agent; nil forgets it.
func (o *MPKeyLifecycleOwner) SetInventory(zone string, snap *KeyInventorySnapshot) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if snap == nil {
		delete(o.inv, lifecycleZoneName(zone))
		return
	}
	o.inv[lifecycleZoneName(zone)] = snap
}

func (o *MPKeyLifecycleOwner) inventoryOf(zone string) *KeyInventorySnapshot {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.inv[lifecycleZoneName(zone)]
}

func (o *MPKeyLifecycleOwner) Name() string { return "tdns-mp" }

// Take makes the owner run zone's key lifecycle from now on. This is the
// per-zone rollout of S3. A zone taken stays owned: one this provider does
// not sign is owned and idle (plan S11), not given back to tdns's machine.
func (o *MPKeyLifecycleOwner) Take(zone string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.owned[lifecycleZoneName(zone)] = true
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

// Owns: a multi-provider zone (tdns asks the same; a zone that is not one
// keeps tdns's machine, whatever the configuration says) whose keys are run
// here (runsKeys), or, on the agent, whose DS answer is computed here.
// taken: taken by name (the loaded zone's options are Owns's business).
func (o *MPKeyLifecycleOwner) taken(zone string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.owned[lifecycleZoneName(zone)]
}

func (o *MPKeyLifecycleOwner) Owns(zd *tdns.ZoneData) bool {
	if zd == nil || !zd.Options[tdns.OptMultiProvider] {
		return false
	}
	if o.runsKeys(zd) {
		return true
	}
	// The agent answers the DS intent of a multi-provider zone its own
	// signer does not own from the signing providers' key states
	// (Amendment 2), and tdns asks Owns to route DSIntentForZone here. The
	// agent's keystore holds none of the zone's DNSSEC keys, so the verbs
	// tdns refuses on an owned zone have nothing there to refuse.
	return o.computedSource() != nil
}

// runsKeys: somebody here runs the zone's key lifecycle. Taken (the
// signer's machine); named in the signer's key-lifecycle-zones with keys
// to sign with, taken or not; or the agent's own signer says so with its
// inventory. This is the answer the pre-S5 CDS rule of the syncher wants
// (syncherPublishesDNSKEYCDS): a zone whose keys are computed about, not
// run, keeps that rule.
//
// A named zone is the machine's from the signer's start (#191), not from
// the take: the take waits for the zone's first load to bind its policy,
// and until then tdns's key worker would mint by tdns's policy and its
// signing path would check the stored keys against it, which mid-way
// through an algorithm rollover refuses to sign. The take only starts the
// driver. A named zone without the keys to sign has never been signed:
// its first keys are tdns's, minted when its policy binds (the machine
// adopts them at the take), and it is owned from the moment they exist.
// Owned before that, tdns's first bind would find no key to sign with,
// undo the binding, and the zone would never be taken.
func (o *MPKeyLifecycleOwner) runsKeys(zd *tdns.ZoneData) bool {
	if zd == nil || !zd.Options[tdns.OptMultiProvider] {
		return false
	}
	zone := lifecycleZoneName(zd.ZoneName)
	o.mu.RLock()
	taken, configured, snap := o.owned[zone], o.configured, o.inv[zone]
	o.mu.RUnlock()
	if taken || (snap != nil && snap.Owned) {
		return true
	}
	if configured == nil || !namedZone(zone, configured()) {
		return false
	}
	return o.hasSigningKeys(zone)
}

// lifecycleZoneName is the key the owner, the engine and the rollout gate file a
// zone under: the FQDN with US-ASCII A-Z lowercased, as tdns keys its
// zones (core.CanonicalizeName; RFC 4343, every other octet as it is). A
// key-lifecycle-zones entry names its zone whatever its case.
func lifecycleZoneName(zone string) string { return core.CanonicalizeName(dns.Fqdn(zone)) }

// namedZone: zone (a lifecycleZoneName) is in names, whatever their case.
func namedZone(zone string, names []string) bool {
	for _, n := range names {
		if core.EqualNames(dns.Fqdn(n), zone) {
			return true
		}
	}
	return false
}

// hasSigningKeys: the keystore holds an active KSK and ZSK of zone (a
// lone KSK counts as both, as a CSK), the test tdns's signing path makes
// before it signs an owned zone; anything less it reads as "not yet". A
// keystore that cannot be read says no.
func (o *MPKeyLifecycleOwner) hasSigningKeys(zone string) bool {
	kdb := o.keyDB()
	if kdb == nil {
		return false
	}
	dak, err := kdb.GetDnssecKeys(zone, tdns.DnskeyStateActive)
	return err == nil && dak != nil && len(dak.KSKs) > 0 && len(dak.ZSKs) > 0
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
	if zd == nil {
		return tdns.DSIntent{}, nil
	}
	var inv []tdns.KeyInventoryItem
	snap := o.inventoryOf(zd.ZoneName)
	if computed := o.computedSource(); snap != nil && snap.Owned {
		// the agent: its own signer's inventory, own and foreign rows
		// alike, as long as it leaves out no DS that the key states from
		// another signing provider's agent put at the parent. Another
		// provider's DS goes when those key states drop it, not when one
		// inventory lacks its key (tdns-mp #207): until the two agree the
		// set is unknown, and the parent's DS is left alone.
		inv = snap.Inventory
		if check := o.foreignDSCheck(); check != nil {
			if why := check(zd.ZoneName, inv); why != "" {
				lgEngine.Warn("the DS set from the signer's inventory is held back; the parent's DS is left as it is", "zone", zd.ZoneName, "why", why)
				return tdns.DSIntent{}, nil
			}
		}
	} else if computed != nil {
		// the agent, for a zone its own signer does not own: what the
		// signing providers said (Amendment 2). An inventory that is not
		// the owner's covers this provider's keys alone and is not the set;
		// the computed answer takes it as this provider's share.
		return computed(zd.ZoneName, digest)
	} else if snap != nil {
		inv = snap.Inventory
	} else {
		kdb := o.keyDB()
		if kdb == nil {
			return tdns.DSIntent{}, nil
		}
		var err error
		inv, err = tdns.GetKeyInventory(kdb, zd.ZoneName)
		if err != nil {
			return tdns.DSIntent{}, fmt.Errorf("DSIntent: inventory of %s: %w", zd.ZoneName, err)
		}
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
// yet; the signer's start names its configured zones (SetConfiguredZones)
// and Take moves a zone onto tdns-mp's machine. It registers the flags of
// the owner's three states with tdns's flag table as well: a foreign row is
// inserted through tdns's one insert without naming its columns, and tdns's
// invariant check wants every state in the store known. tdns carries the
// same entries only while it still names the states (design S4 drops them
// with the hooks); this registration is what keeps them after that.
func RegisterMPKeyLifecycleOwner(conf *Config) *MPKeyLifecycleOwner {
	o := NewMPKeyLifecycleOwner(func() *tdns.KeyDB {
		if conf == nil || conf.Config == nil {
			return nil
		}
		return conf.Config.Internal.KeyDB
	})
	registerOwnerKeyStateFlags()
	tdns.RegisterKeyLifecycleOwner(o)
	return o
}

// registerOwnerKeyStateFlags tells tdns's keystore what a row in one of the
// owner's states does (design §3.4): served but not signing while
// distributed to the peers or foreign, neither once parked for removal.
// tdns carries no entry for these states itself (S4), and its keystore
// refuses a row in a state it has no flags for, so the registration is
// made once at package init, before any keystore opens, in daemons and
// tests alike; RegisterMPKeyLifecycleOwner repeats it, which is harmless.
func registerOwnerKeyStateFlags() {
	tdns.RegisterKeyStateFlags(map[string]tdns.KeyRowFlags{
		DnskeyStateMpdist:   {Pub: true},
		DnskeyStateForeign:  {Pub: true},
		DnskeyStateMpremove: {},
	})
}

func init() { registerOwnerKeyStateFlags() }
