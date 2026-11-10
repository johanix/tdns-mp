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
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// servedAnswer is one address's answer to the serving check's query: the
// zone's SOA RRset with its RRSIGs, or why there is none.
type servedAnswer struct {
	Addr  string
	RRset *core.RRset
	Err   error
}

// servingLookup asks each address of the nameserver ns, found by name, for
// the zone's SOA RRset with its RRSIGs: an answer per address. A test
// stands in for it.
var servingLookup = imrServingLookup

// imrServingLookup finds ns's addresses through the IMR and asks each of
// them, without recursion and with DNSSEC OK, for the zone's SOA. Each on
// its own: over a list of addresses AuthDNSQuery takes the first that
// answers, and another address of the same name can serve an older or an
// unsigned copy.
func imrServingLookup(ctx context.Context, zone, ns string) ([]servedAnswer, error) {
	imr := tdns.Globals.ImrEngine
	if imr == nil {
		return nil, errors.New("the IMR is not running")
	}
	var addrs []string
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := imr.ImrQuery(ctx, ns, qtype, dns.ClassINET, nil)
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
	answers := make([]servedAnswer, 0, len(addrs))
	for _, addr := range addrs {
		a := servedAnswer{Addr: addr}
		rrset, rcode, _, err := imr.AuthDNSQuery(ctx, zone, dns.TypeSOA, []string{addr}, log.Default(), false)
		switch {
		case err != nil:
			a.Err = err
		case rrset == nil:
			// NODATA, NXDOMAIN or a referral: no error, and no RRset
			a.Err = fmt.Errorf("no SOA in the answer (%s)", dns.RcodeToString[rcode])
		default:
			a.RRset = rrset
		}
		answers = append(answers, a)
	}
	return answers, nil
}

// servingChainOK: each of the nameservers serves the zone, at each of its
// addresses, at an SOA serial no lower than minSerial (RFC 1982), signed by
// the expected signers: there is an RRSIG over the SOA, and each is by one
// of keys, in its validity period, and verifies. It returns the lowest
// serial served, and why the check fails.
func servingChainOK(ctx context.Context, zone string, nameservers []string, keys []dns.RR, minSerial uint32, now time.Time) (uint32, error) {
	if len(nameservers) == 0 {
		return 0, errors.New("multi-provider.local.nameservers names none")
	}
	if len(keys) == 0 {
		return 0, errors.New("no DNSKEY of the expected signers is known here")
	}
	var lowest uint32
	seen := false
	for _, ns := range nameservers {
		answers, err := servingLookup(ctx, zone, ns)
		if err != nil {
			return lowest, fmt.Errorf("%s: %w", ns, err)
		}
		if len(answers) == 0 {
			return lowest, fmt.Errorf("%s serves no SOA for the zone", ns)
		}
		for _, a := range answers {
			at := ns
			if a.Addr != "" {
				at = ns + " at " + a.Addr
			}
			if a.Err != nil {
				return lowest, fmt.Errorf("%s: %w", at, a.Err)
			}
			var soa *dns.SOA
			if a.RRset != nil {
				for _, rr := range a.RRset.RRs {
					if s, ok := rr.(*dns.SOA); ok {
						soa = s
					}
				}
			}
			if soa == nil {
				return lowest, fmt.Errorf("%s serves no SOA for the zone", at)
			}
			if !seen || CompareSerial(soa.Serial, lowest) < 0 {
				lowest, seen = soa.Serial, true
			}
			if CompareSerial(soa.Serial, minSerial) < 0 {
				return lowest, fmt.Errorf("%s serves serial %d, below %d", at, soa.Serial, minSerial)
			}
			if err := signedByOneOf(a.RRset, keys, now); err != nil {
				return lowest, fmt.Errorf("%s: %w", at, err)
			}
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
