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
	"net"
	"slices"
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// errIMRNotRunning: nothing can be asked of a nameserver here yet. It says nothing
// of what the nameserver serves.
var errIMRNotRunning = errors.New("the IMR is not running")

// errServesNoRRset: the nameserver answers for the name, with NODATA or NXDOMAIN,
// and holds no RRset of the type.
var errServesNoRRset = errors.New("it serves no such RRset")

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

// servingKeysLookup asks the nameserver ns, by name, for the zone's DNSKEY
// RRset (imrServingQuery). A test stands in for it.
var servingKeysLookup = func(ctx context.Context, zone, ns string) (*core.RRset, error) {
	return imrServingQuery(ctx, zone, ns, dns.TypeDNSKEY)
}

// imrServingLookup asks each of ns's addresses (servingAddrs) on its own for
// the zone's SOA (askServing): over a list of addresses the first that
// answers is taken, and another address of the same name can serve an older
// or an unsigned copy. A failure's error names its address already.
func imrServingLookup(ctx context.Context, zone, ns string) ([]servedAnswer, error) {
	addrs, err := servingAddrs(ctx, ns)
	if err != nil {
		return nil, err
	}
	answers := make([]servedAnswer, 0, len(addrs))
	for _, addr := range addrs {
		rrset, err := askServing(ctx, zone, dns.TypeSOA, []string{addr})
		a := servedAnswer{RRset: rrset, Err: err}
		if err == nil {
			a.Addr = addr
		}
		answers = append(answers, a)
	}
	return answers, nil
}

// servingAskTimeout bounds one exchange with one address of a nameserver.
const servingAskTimeout = 2 * time.Second

// imrServingQuery asks ns's addresses (servingAddrs) for the zone's RRset of
// qtype (askServing): the first that answers.
func imrServingQuery(ctx context.Context, zone, ns string, qtype uint16) (*core.RRset, error) {
	addrs, err := servingAddrs(ctx, ns)
	if err != nil {
		return nil, err
	}
	return askServing(ctx, zone, qtype, addrs)
}

// servingAddrs are ns's addresses, found through the IMR, each with its port.
func servingAddrs(ctx context.Context, ns string) ([]string, error) {
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
	return addrs, nil
}

// askServing asks addrs in turn, each a host and port, without recursion and with
// DNSSEC OK, for the zone's RRset of qtype, until one answers for the name. It asks
// them itself: tdns's AuthDNSQuery stores what it reads in the IMR's cache, unvalidated
// and over what the cache holds. A nameserver answering NODATA had the resolver deny
// the zone's DNSKEY RRset, so it could validate nothing of the zone's, and one answering
// with a referral gave it that referral's NS RRset for the zone.
func askServing(ctx context.Context, zone string, qtype uint16, addrs []string) (*core.RRset, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), qtype)
	m.RecursionDesired = false
	m.SetEdns0(4096, true)
	var last error
	for _, addr := range addrs {
		r, err := exchangeServing(ctx, m, addr)
		if err != nil {
			last = fmt.Errorf("%s: %w", addr, err)
			continue
		}
		rrset, answered, err := readServed(r, m, qtype)
		if answered {
			return rrset, err
		}
		last = fmt.Errorf("%s: %w", addr, err)
	}
	if last == nil {
		last = errors.New("no address to ask")
	}
	return nil, last
}

// exchangeServing asks addr over UDP and, when the reply is truncated, over TCP: what
// a truncated reply leaves out says nothing of what the server serves, and post-quantum
// keys take a DNSKEY RRset past the buffer. No reply over TCP, or one truncated there
// as well, is an error: the server has not answered.
func exchangeServing(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
	r, _, err := (&dns.Client{Net: "udp", Timeout: servingAskTimeout}).ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, err
	}
	if !r.Truncated {
		return r, nil
	}
	r, _, err = (&dns.Client{Net: "tcp", Timeout: servingAskTimeout}).ExchangeContext(ctx, m, addr)
	switch {
	case err != nil:
		return nil, fmt.Errorf("a truncated reply, and over TCP: %w", err)
	case r.Truncated:
		return nil, errors.New("a truncated reply, over TCP as well")
	}
	return r, nil
}

// enclosingSOA: r's authority section holds the SOA of a zone at or above
// name, as an authoritative NODATA or NXDOMAIN does and a referral does not.
func enclosingSOA(r *dns.Msg, name string) bool {
	return slices.ContainsFunc(r.Ns, func(rr dns.RR) bool {
		_, ok := rr.(*dns.SOA)
		return ok && dns.IsSubDomain(rr.Header().Name, name)
	})
}

// readServed reads a whole reply to query. It has answered when it says what the
// server does with the name: the RRset, errServesNoRRset when it serves the name
// without one, or a referral, which is an error of its own as the server does not
// serve the zone. Otherwise the error says why not, and another address may be asked.
// The RRset is the name's, and its RRSIGs those over it: another owner's records, or
// a signature over another type, are no part of it.
func readServed(r, query *dns.Msg, qtype uint16) (rrset *core.RRset, answered bool, err error) {
	q := query.Question[0]
	if len(r.Question) != 1 || !sameName(r.Question[0].Name, q.Name) || r.Question[0].Qtype != q.Qtype || r.Question[0].Qclass != q.Qclass {
		return nil, false, errors.New("a reply to another question")
	}
	noRRset := fmt.Errorf("no %s in the answer (%s): %w", dns.TypeToString[qtype], dns.RcodeToString[r.Rcode], errServesNoRRset)
	soa := enclosingSOA(r, q.Name)
	switch r.Rcode {
	case dns.RcodeSuccess:
		served := &core.RRset{}
		for _, rr := range r.Answer {
			if !sameName(rr.Header().Name, q.Name) {
				continue
			}
			switch rr.Header().Rrtype {
			case qtype:
				served.RRs = append(served.RRs, rr)
			case dns.TypeRRSIG:
				if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == qtype {
					served.RRSIGs = append(served.RRSIGs, rr)
				}
			}
		}
		switch {
		case len(served.RRs) > 0:
			return served, true, nil
		case len(r.Answer) == 0 && len(r.Ns) > 0 && !soa:
			// it does not serve the zone: a resolver goes on to another
			return nil, true, fmt.Errorf("a referral, not an answer, for %s", dns.TypeToString[qtype])
		}
		return nil, true, noRRset
	case dns.RcodeNameError:
		if soa {
			return nil, true, noRRset
		}
		return nil, false, errors.New("NXDOMAIN with no SOA")
	}
	return nil, false, fmt.Errorf("rcode %s", dns.RcodeToString[r.Rcode])
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
	return servingSOAs(ctx, zone, nameservers, minSerial, func(rrset *core.RRset) error { return signedByOneOf(rrset, keys, now) })
}

// servingSerialOK: each of the nameservers serves the zone, at each of its
// addresses, at an SOA serial no lower than minSerial (RFC 1982), signed or
// not: the check where no provider's key signs the copy they serve.
func servingSerialOK(ctx context.Context, zone string, nameservers []string, minSerial uint32) (uint32, error) {
	if len(nameservers) == 0 {
		return 0, errors.New("multi-provider.local.nameservers names none")
	}
	return servingSOAs(ctx, zone, nameservers, minSerial, nil)
}

// servingSOAs asks each address of each of the nameservers for the zone's
// SOA: its serial no lower than minSerial, and signed passes, unless nil.
// It returns the lowest serial served, and why the check fails.
func servingSOAs(ctx context.Context, zone string, nameservers []string, minSerial uint32, signed func(*core.RRset) error) (uint32, error) {
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
			if signed == nil {
				continue
			}
			if err := signed(a.RRset); err != nil {
				return lowest, fmt.Errorf("%s: %w", at, err)
			}
		}
	}
	return lowest, nil
}

// signedByOneOf: rrset has an RRSIG, and each is by one of keys, valid at
// now, and verifies. Keys can share a key tag, algorithm and signer: an
// RRSIG verifies when one of the keys that match it verifies it.
func signedByOneOf(rrset *core.RRset, keys []dns.RR, now time.Time) error {
	if len(rrset.RRSIGs) == 0 {
		return errors.New("the SOA is not signed")
	}
	for _, rr := range rrset.RRSIGs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		var matching []*dns.DNSKEY
		for _, k := range keys {
			if dk, ok := k.(*dns.DNSKEY); ok && dk.KeyTag() == sig.KeyTag && dk.Algorithm == sig.Algorithm && core.EqualNames(dk.Hdr.Name, sig.SignerName) {
				matching = append(matching, dk)
			}
		}
		switch {
		case len(matching) == 0:
			return fmt.Errorf("the SOA's RRSIG by key %d is by none of the expected signers' keys", sig.KeyTag)
		case !sig.ValidityPeriod(now):
			return fmt.Errorf("the SOA's RRSIG by key %d is outside its validity period", sig.KeyTag)
		}
		var err error
		for _, dk := range matching {
			if err = sig.Verify(dk, rrset.RRs); err == nil {
				break
			}
		}
		if err != nil {
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
// copy, for its DNSKEY RRset, under a bound of its own, and looks for keys in it.
// An error says the look says nothing of them: the copy names none, or nothing can
// be asked.
func lookForJoinerKeys(mpzd *MPZoneData, keys []*dns.DNSKEY) (joinerKeysServed, error) {
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
		rrset, err := servingKeysLookup(ctx, mpzd.ZoneName, ns)
		cancel()
		switch {
		case errors.Is(err, errIMRNotRunning):
			return joinerKeysServed{}, err
		case err != nil && !errors.Is(err, errServesNoRRset):
			seen.silent, seen.why = append(seen.silent, ns), fmt.Errorf("%s: %w", ns, err)
			continue
		}
		ttl, _ := dnskeyTTLOf(rrset)
		seen.ttl = max(seen.ttl, ttl)
		if servesKeys(rrset, keys) {
			seen.with = append(seen.with, ns)
		} else {
			seen.without = append(seen.without, ns)
		}
	}
	return seen, nil
}

// servesKeys: rrset holds each of keys, the key and not just its tag. A signer
// can't record another's key under a tag of its own (syncForeignDNSKEYs), so it
// goes on serving its own there, and that isn't the joiner's. A nil key, one whose
// record can't be read, is held by no RRset.
func servesKeys(rrset *core.RRset, keys []*dns.DNSKEY) bool {
	if rrset == nil {
		return false
	}
	for _, key := range keys {
		if key == nil || !slices.ContainsFunc(rrset.RRs, func(rr dns.RR) bool { return dns.IsDuplicate(key, rr) }) {
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
