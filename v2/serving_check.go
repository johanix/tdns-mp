/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The serving check (design 5.1, plan S18a): whether this provider's own
 * nameservers, named in multi-provider.local.nameservers, serve the zone
 * from its upstream. Each is found through the IMR and asked for the zone's
 * SOA: its serial is no lower than the zone's, and every RRSIG over it is
 * by a key of the expected signers and verifies. A server role's step is
 * held at the provider's agent only once the check passes: the transfer
 * confirmation (server_role.go).
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"slices"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// servingLookup asks the nameserver ns, by name, for the zone's SOA RRset
// with its RRSIGs. A test stands in for it.
var servingLookup = imrServingLookup

// servingKeysLookup is servingLookup for the zone's DNSKEY RRset.
var servingKeysLookup = func(ctx context.Context, zone, ns string) (*core.RRset, error) {
	return imrServingQuery(ctx, zone, ns, dns.TypeDNSKEY)
}

// imrServingLookup asks ns for the zone's SOA (imrServingQuery).
func imrServingLookup(ctx context.Context, zone, ns string) (*core.RRset, error) {
	return imrServingQuery(ctx, zone, ns, dns.TypeSOA)
}

// imrServingQuery finds ns's addresses through the IMR and asks them,
// without recursion and with DNSSEC OK, for the zone's RRset of qtype.
func imrServingQuery(ctx context.Context, zone, ns string, qtype uint16) (*core.RRset, error) {
	imr := tdns.Globals.ImrEngine
	if imr == nil {
		return nil, errors.New("the IMR is not running")
	}
	var addrs []string
	for _, addrType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := imr.ImrQuery(ctx, ns, addrType, dns.ClassINET, nil)
		if err != nil || resp == nil || resp.RRset == nil {
			continue
		}
		// with the port: AuthDNSQuery adds it only to an address that
		// does not end in ":53", which an IPv6 address can
		for _, rr := range resp.RRset.RRs {
			switch a := rr.(type) {
			case *dns.A:
				addrs = append(addrs, net.JoinHostPort(a.A.String(), "53"))
			case *dns.AAAA:
				addrs = append(addrs, net.JoinHostPort(a.AAAA.String(), "53"))
			}
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("the IMR finds no address for %s", ns)
	}
	rrset, rcode, _, err := imr.AuthDNSQuery(ctx, zone, qtype, addrs, log.Default(), false)
	switch {
	case err != nil:
		return nil, err
	case rrset == nil:
		// NODATA, NXDOMAIN or a referral: no error, and no RRset
		return nil, fmt.Errorf("no %s in the answer (%s)", dns.TypeToString[qtype], dns.RcodeToString[rcode])
	}
	return rrset, nil
}

// highestServedSerial is the highest SOA serial the nameservers serve for the zone
// (RFC 1982): what they served, for an upstream's step (other_keys.go). Each
// must answer.
func highestServedSerial(ctx context.Context, zone string, nameservers []string) (uint32, error) {
	if len(nameservers) == 0 {
		return 0, errors.New("multi-provider.local.nameservers names none")
	}
	var highest uint32
	for i, ns := range nameservers {
		rrset, err := servingLookup(ctx, zone, ns)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", ns, err)
		}
		var soa *dns.SOA
		if rrset != nil {
			for _, rr := range rrset.RRs {
				if s, ok := rr.(*dns.SOA); ok {
					soa = s
				}
			}
		}
		if soa == nil {
			return 0, fmt.Errorf("%s serves no SOA for the zone", ns)
		}
		if i == 0 || CompareSerial(soa.Serial, highest) > 0 {
			highest = soa.Serial
		}
	}
	return highest, nil
}

// servingChainOK: each of the nameservers serves the zone at an SOA serial
// no lower than minSerial (RFC 1982), signed by the expected signers: there
// is an RRSIG over the SOA, and each is by one of keys, in its validity
// period, and verifies. It returns the lowest serial served, and why the
// check fails.
func servingChainOK(ctx context.Context, zone string, nameservers []string, keys []dns.RR, minSerial uint32, now time.Time) (uint32, error) {
	if len(nameservers) == 0 {
		return 0, errors.New("multi-provider.local.nameservers names none")
	}
	if len(keys) == 0 {
		return 0, errors.New("no DNSKEY of the expected signers is known here")
	}
	var lowest uint32
	for i, ns := range nameservers {
		rrset, err := servingLookup(ctx, zone, ns)
		if err != nil {
			return lowest, fmt.Errorf("%s: %w", ns, err)
		}
		if rrset == nil {
			return lowest, fmt.Errorf("%s serves no SOA for the zone", ns)
		}
		var soa *dns.SOA
		for _, rr := range rrset.RRs {
			if s, ok := rr.(*dns.SOA); ok {
				soa = s
			}
		}
		if soa == nil {
			return lowest, fmt.Errorf("%s serves no SOA for the zone", ns)
		}
		if i == 0 || CompareSerial(soa.Serial, lowest) < 0 {
			lowest = soa.Serial
		}
		if CompareSerial(soa.Serial, minSerial) < 0 {
			return lowest, fmt.Errorf("%s serves serial %d, below %d", ns, soa.Serial, minSerial)
		}
		if err := signedByOneOf(rrset, keys, now); err != nil {
			return lowest, fmt.Errorf("%s: %w", ns, err)
		}
	}
	return lowest, nil
}

// signedByOneOf: rrset has an RRSIG, and each is by one of keys, valid at
// now, and verifies.
func signedByOneOf(rrset *core.RRset, keys []dns.RR, now time.Time) error {
	if len(rrset.RRSIGs) == 0 {
		return errors.New("the SOA is not signed")
	}
	for _, rr := range rrset.RRSIGs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		i := slices.IndexFunc(keys, func(k dns.RR) bool {
			dk, ok := k.(*dns.DNSKEY)
			return ok && dk.KeyTag() == sig.KeyTag && dk.Algorithm == sig.Algorithm && core.EqualNames(dk.Hdr.Name, sig.SignerName)
		})
		switch {
		case i < 0:
			return fmt.Errorf("the SOA's RRSIG by key %d is by none of the expected signers' keys", sig.KeyTag)
		case !sig.ValidityPeriod(now):
			return fmt.Errorf("the SOA's RRSIG by key %d is outside its validity period", sig.KeyTag)
		}
		if err := sig.Verify(keys[i].(*dns.DNSKEY), rrset.RRs); err != nil {
			return fmt.Errorf("the SOA's RRSIG by key %d does not verify: %w", sig.KeyTag, err)
		}
	}
	return nil
}

// servesOwnSignatures: each of the nameservers serves the zone from this
// provider's own signer (design 5.1, plan S18b): a DNSKEY RRset with an RRSIG by
// one of its KSKs among keys, in its validity period, that verifies, at an SOA
// serial above the one they served (above, when aboveKnown). The RRset is the
// zone's whole, and other signatures on it are not this check's.
func servesOwnSignatures(ctx context.Context, zone string, nameservers []string, keys []dns.RR, above uint32, aboveKnown bool, now time.Time) error {
	if len(nameservers) == 0 {
		return errors.New("multi-provider.local.nameservers names none")
	}
	var ksks []*dns.DNSKEY
	for _, k := range keys {
		if dk, ok := k.(*dns.DNSKEY); ok && dk.Flags&dns.SEP != 0 {
			ksks = append(ksks, dk)
		}
	}
	if len(ksks) == 0 {
		return errors.New("no KSK of this provider's is known here")
	}
	if aboveKnown {
		for _, ns := range nameservers {
			served, err := highestServedSerial(ctx, zone, []string{ns})
			if err != nil {
				return err
			}
			if CompareSerial(served, above) <= 0 {
				return fmt.Errorf("%s serves serial %d, not above %d", ns, served, above)
			}
		}
	}
	for _, ns := range nameservers {
		rrset, err := servingKeysLookup(ctx, zone, ns)
		if err != nil {
			return fmt.Errorf("%s: %w", ns, err)
		}
		if rrset == nil || !signedByOwnKSK(rrset, ksks, now) {
			return fmt.Errorf("%s serves no DNSKEY RRset signed by this provider's KSK", ns)
		}
	}
	return nil
}

// signedByOwnKSK: rrset has an RRSIG by one of ksks, valid at now, that verifies.
func signedByOwnKSK(rrset *core.RRset, ksks []*dns.DNSKEY, now time.Time) bool {
	return slices.ContainsFunc(rrset.RRSIGs, func(rr dns.RR) bool {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || !sig.ValidityPeriod(now) {
			return false
		}
		return slices.ContainsFunc(ksks, func(dk *dns.DNSKEY) bool {
			return dk.KeyTag() == sig.KeyTag && dk.Algorithm == sig.Algorithm && sig.Verify(dk, rrset.RRs) == nil
		})
	})
}

// dnskeyTTLOf is the largest TTL among rrset's DNSKEYs, and whether it holds one.
func dnskeyTTLOf(rrset *core.RRset) (time.Duration, bool) {
	var largest time.Duration
	found := false
	if rrset != nil {
		for _, rr := range rrset.RRs {
			if _, ok := rr.(*dns.DNSKEY); ok {
				largest, found = max(largest, time.Duration(rr.Header().Ttl)*time.Second), true
			}
		}
	}
	return largest, found
}

// largestServedDnskeyTTL is the largest TTL any of the zone's nameservers, by the
// NS RRset of its copy, serves its DNSKEY RRset with. Each is asked under a bound of
// its own. One that does not answer with the RRset hands it to nobody; with none
// that does nothing is known.
func largestServedDnskeyTTL(mpzd *MPZoneData) (time.Duration, error) {
	rrset, err := mpzd.GetRRset(mpzd.ZoneName, dns.TypeNS)
	if err != nil {
		return 0, err
	}
	var largest time.Duration
	found := false
	last := errors.New("the zone's copy names no nameserver")
	if rrset != nil {
		for _, rr := range rrset.RRs {
			ns, ok := rr.(*dns.NS)
			if !ok {
				continue
			}
			ctx, cancel := lookCtx()
			keys, err := servingKeysLookup(ctx, mpzd.ZoneName, ns.Ns)
			cancel()
			if err != nil {
				last = fmt.Errorf("%s: %w", ns.Ns, err)
				continue
			}
			if ttl, ok := dnskeyTTLOf(keys); ok {
				largest, found = max(largest, ttl), true
			} else {
				last = fmt.Errorf("%s serves no DNSKEY for the zone", ns.Ns)
			}
		}
	}
	if !found {
		return 0, last
	}
	return largest, nil
}

// servedKeysEvery is how often a signer asks a zone it does not sign yet's
// nameservers what they serve its DNSKEY RRset with.
const servedKeysEvery = time.Minute

// servedKeysBook is what a signer has seen the nameservers of the zones it does
// not sign yet serve their DNSKEY RRsets with, by zone. In memory: after a restart
// it looks again.
type servedKeysBook struct {
	mu    sync.Mutex
	zones map[string]*servedKeysLook
	// start runs a look; nil: in a goroutine of its own. A test runs it in place.
	start func(look func())
}

type servedKeysLook struct {
	ttl     time.Duration // the largest seen: a cache may hold what was served before
	known   bool
	said    bool // that nothing is known, once
	at      time.Time
	running bool
}

// largest is the largest TTL seen for the zone, and whether any server has
// answered. It never waits for a look: it runs under the key machine's lock.
func (b *servedKeysBook) largest(mpzd *MPZoneData) (time.Duration, bool) {
	zone := mpzd.ZoneName
	key := canonicalName(zone)
	b.mu.Lock()
	if b.zones == nil {
		b.zones = map[string]*servedKeysLook{}
	}
	l := b.zones[key]
	if l == nil {
		l = &servedKeysLook{}
		b.zones[key] = l
	}
	due := !l.running && time.Since(l.at) >= servedKeysEvery
	if due {
		l.running = true
	}
	start := b.start
	b.mu.Unlock()
	if due {
		look := func() {
			ttl, err := largestServedDnskeyTTL(mpzd)
			b.mu.Lock()
			l.running, l.at = false, time.Now()
			grew, warn := err == nil && (!l.known || ttl > l.ttl), err != nil && !l.known && !l.said
			if err == nil {
				l.ttl, l.known = max(l.ttl, ttl), true
			} else {
				l.said = true
			}
			b.mu.Unlock()
			switch {
			case grew:
				lgSigner.Info("the zone's new keys wait the TTL its servers serve its DNSKEY RRset with", "zone", zone, "ttl", ttl)
			case warn:
				lgSigner.Warn("what the zone's servers serve its DNSKEY RRset with could not be read; its new keys wait its copy's TTL", "zone", zone, "err", err)
			}
		}
		if start != nil {
			start(look)
		} else {
			go look()
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return l.ttl, l.known
}
