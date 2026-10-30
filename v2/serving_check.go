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
	"slices"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// servingLookup asks the nameserver ns, by name, for the zone's SOA RRset
// with its RRSIGs. A test stands in for it.
var servingLookup = imrServingLookup

// imrServingLookup finds ns's addresses through the IMR and asks them,
// without recursion and with DNSSEC OK, for the zone's SOA.
func imrServingLookup(ctx context.Context, zone, ns string) (*core.RRset, error) {
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
		for _, rr := range resp.RRset.RRs {
			switch a := rr.(type) {
			case *dns.A:
				addrs = append(addrs, a.A.String())
			case *dns.AAAA:
				addrs = append(addrs, a.AAAA.String())
			}
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("the IMR finds no address for %s", ns)
	}
	rrset, _, _, err := imr.AuthDNSQuery(ctx, zone, dns.TypeSOA, addrs, log.Default(), false)
	if err != nil {
		return nil, err
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
