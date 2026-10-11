/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Where the leader publishes its SIG(0) KEY for the parent to find.
 */

package tdnsmp

import "github.com/miekg/dns"

// publishLocations is where the leader's SIG(0) KEY goes for the parent's
// key bootstrap: the zone's apex always (at-apex), and the RFC 9615 signal
// names under each of the zone's nameservers (at-ns) only when the zone's
// HSYNCPARAM carries the pubkey flag. The flag is the customer's word that
// its providers may publish the zone's key in zones of their own; without
// it the combiners publish nothing there. A parent that requires DNSSEC of
// a child cannot validate the apex KEY of a zone that has no DS yet, only
// the signal name in a provider's signed zone, so a customer wanting that
// parent says pubkey.
func publishLocations(zone ZoneName) []string {
	locs := []string{"at-apex"}
	if mpzd, ok := Zones.Get(dns.Fqdn(string(zone))); ok && mpzd != nil {
		if hp := mpzd.getHSYNCPARAM(); hp != nil && hp.HasPubkey() {
			locs = append(locs, "at-ns")
		}
	}
	return locs
}
