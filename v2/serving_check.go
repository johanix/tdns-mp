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
	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// errIMRNotRunning: nothing can be asked of a nameserver here yet. It says nothing
// of what the nameserver serves.
var errIMRNotRunning = errors.New("the IMR is not running")

// errServesNoRRset: the nameserver answers for the name, with NODATA or NXDOMAIN,
// and holds no RRset of the type.
var errServesNoRRset = errors.New("it serves no such RRset")

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
		return nil, errIMRNotRunning
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
	rrset, rcode, answer, err := imr.AuthDNSQuery(ctx, zone, qtype, addrs, log.Default(), false)
	switch {
	case err != nil:
		return nil, err
	case rrset == nil && answer == cache.ContextReferral:
		// it does not serve the zone: a resolver goes on to another
		return nil, fmt.Errorf("a referral, not an answer, for %s", dns.TypeToString[qtype])
	case rrset == nil:
		// NODATA or NXDOMAIN: no error, and no RRset
		return nil, fmt.Errorf("no %s in the answer (%s): %w", dns.TypeToString[qtype], dns.RcodeToString[rcode], errServesNoRRset)
	}
	return rrset, nil
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
// NS RRset of its copy, serves its DNSKEY RRset with, the servers that served it and
// those that did not, and why the last of those did not. Each is asked under a bound
// of its own.
func largestServedDnskeyTTL(mpzd *MPZoneData) (largest time.Duration, served, silent []string, err error) {
	names, err := copyNameservers(mpzd)
	if err != nil {
		return 0, nil, nil, err
	}
	for _, ns := range names {
		ctx, cancel := lookCtx()
		keys, lookErr := servingKeysLookup(ctx, mpzd.ZoneName, ns)
		cancel()
		ttl, found := dnskeyTTLOf(keys)
		switch {
		case lookErr != nil:
			err = fmt.Errorf("%s: %w", ns, lookErr)
		case !found:
			err = fmt.Errorf("%s serves no DNSKEY for the zone", ns)
		default:
			largest = max(largest, ttl)
			served = append(served, ns)
			continue
		}
		silent = append(silent, ns)
	}
	if len(served) == 0 && err == nil {
		err = errors.New("the zone's copy names no nameserver")
	}
	return largest, served, silent, err
}

// copyNameservers are the nameservers the NS RRset of the zone's copy names.
func copyNameservers(mpzd *MPZoneData) ([]string, error) {
	rrset, err := mpzd.GetRRset(mpzd.ZoneName, dns.TypeNS)
	if err != nil || rrset == nil {
		return nil, err
	}
	var names []string
	for _, rr := range rrset.RRs {
		if ns, ok := rr.(*dns.NS); ok {
			names = append(names, ns.Ns)
		}
	}
	return names, nil
}

// copyDnskeyTTL is the TTL of the DNSKEY RRset of the zone's copy; with none,
// tdns's default.
func copyDnskeyTTL(mpzd *MPZoneData) time.Duration {
	if rrset, err := mpzd.GetRRset(mpzd.ZoneName, dns.TypeDNSKEY); err == nil {
		if ttl, ok := dnskeyTTLOf(rrset); ok {
			return ttl
		}
	}
	return tdns.DefaultDnskeyTTL
}

// joinerKeysServed is what one look found of a joiner's keys at the zone's
// nameservers: those that answer with them all, those that answer without, and those
// that do not answer, with why the last of those did not; the largest TTL any serves
// the zone's DNSKEY RRset with; and the TTL of the RRset of the zone's copy.
type joinerKeysServed struct {
	with, without, silent []string
	why                   error
	ttl, copyTTL          time.Duration
}

// lookForJoinerKeys asks each of the zone's nameservers, by the NS RRset of its
// copy, for its DNSKEY RRset, under a bound of its own, and looks for the keys tags.
// An error says the look says nothing of them: the copy names none, or nothing can
// be asked.
func lookForJoinerKeys(mpzd *MPZoneData, tags []uint16) (joinerKeysServed, error) {
	names, err := copyNameservers(mpzd)
	if err != nil {
		return joinerKeysServed{}, err
	}
	if len(names) == 0 {
		return joinerKeysServed{}, errors.New("the zone's copy names no nameserver")
	}
	seen := joinerKeysServed{copyTTL: copyDnskeyTTL(mpzd)}
	for _, ns := range names {
		ctx, cancel := lookCtx()
		keys, err := servingKeysLookup(ctx, mpzd.ZoneName, ns)
		cancel()
		switch {
		case errors.Is(err, errIMRNotRunning):
			return joinerKeysServed{}, err
		case err != nil && !errors.Is(err, errServesNoRRset):
			seen.silent, seen.why = append(seen.silent, ns), fmt.Errorf("%s: %w", ns, err)
			continue
		}
		ttl, _ := dnskeyTTLOf(keys)
		seen.ttl = max(seen.ttl, ttl)
		if servesKeyTags(keys, tags) {
			seen.with = append(seen.with, ns)
		} else {
			seen.without = append(seen.without, ns)
		}
	}
	return seen, nil
}

// servesKeyTags: rrset holds a DNSKEY of each of tags.
func servesKeyTags(rrset *core.RRset, tags []uint16) bool {
	if rrset == nil {
		return false
	}
	for _, tag := range tags {
		if !slices.ContainsFunc(rrset.RRs, func(rr dns.RR) bool {
			dk, ok := rr.(*dns.DNSKEY)
			return ok && dk.KeyTag() == tag
		}) {
			return false
		}
	}
	return true
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
	ttl     time.Duration   // the largest seen: a cache may hold what was served before
	served  map[string]bool // the servers seen serving it: one gone quiet has served what it served
	whole   bool            // every server the copy names has been seen serving it
	looked  bool            // a look has finished since the start
	said    bool            // that it is not whole, once
	at      time.Time
	running bool
}

// largest is the largest TTL seen for the zone, whether every nameserver its copy
// names has been seen serving the RRset, and whether a look has finished since the
// start. It never waits for a look: it runs under the key machine's lock.
func (b *servedKeysBook) largest(mpzd *MPZoneData) (ttl time.Duration, whole, looked bool) {
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
			seen, served, silent, err := largestServedDnskeyTTL(mpzd)
			b.mu.Lock()
			l.running, l.at, l.looked = false, time.Now(), true
			before, wasWhole := l.ttl, l.whole
			l.ttl = max(l.ttl, seen)
			if l.served == nil {
				l.served = map[string]bool{}
			}
			for _, ns := range served {
				l.served[canonicalName(ns)] = true
			}
			missing := slices.DeleteFunc(silent, func(ns string) bool { return l.served[canonicalName(ns)] })
			// a look that could list no server says nothing of them all
			l.whole = len(served)+len(silent) > 0 && len(l.served) > 0 && len(missing) == 0
			grew, warn := l.whole && (!wasWhole || l.ttl > before), !l.whole && !l.said
			l.said = l.said || warn
			now := l.ttl
			b.mu.Unlock()
			switch {
			case grew:
				lgSigner.Info("the zone's new keys wait the TTL its servers serve its DNSKEY RRset with", "zone", zone, "ttl", now)
			case warn:
				lgSigner.Warn("not every server of the zone has served its DNSKEY RRset; its new keys wait at least its copy's TTL", "zone", zone, "silent", missing, "err", err)
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
	return l.ttl, l.whole, l.looked
}

// lookCtx is one look's context, with its bound.
func lookCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), transferCheckTimeout)
}
