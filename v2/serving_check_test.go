package tdnsmp

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// servingListener is a nameserver on a loopback port of its own, UDP and, unless it
// has none, TCP. answer writes the reply to a query, over the transport named.
func servingListener(t *testing.T, withTCP bool, answer func(q *dns.Msg, overTCP bool) *dns.Msg) string {
	t.Helper()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		if r := answer(q, w.LocalAddr().Network() == "tcp"); r != nil {
			w.WriteMsg(r)
		}
	})
	serve := func(s *dns.Server) {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go s.ActivateAndServe()
		<-started
		t.Cleanup(func() { s.Shutdown() })
	}
	for range 10 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := pc.LocalAddr().String()
		if !withTCP {
			serve(&dns.Server{PacketConn: pc, Handler: handler})
			return addr
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			pc.Close() // that port is taken for TCP: another
			continue
		}
		serve(&dns.Server{PacketConn: pc, Handler: handler})
		serve(&dns.Server{Listener: l, Handler: handler})
		return addr
	}
	t.Fatal("no port free for both UDP and TCP")
	return ""
}

const servingTestZone = "asked.example."

func servingReply(q *dns.Msg, rcode int, answer, authority []string) *dns.Msg {
	r := new(dns.Msg)
	r.SetRcode(q, rcode)
	for _, s := range answer {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		r.Answer = append(r.Answer, rr)
	}
	for _, s := range authority {
		rr, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		r.Ns = append(r.Ns, rr)
	}
	return r
}

const (
	servingKSK    = servingTestZone + " 300 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
	servingZSK    = servingTestZone + " 300 IN DNSKEY 256 3 15 cDrOBkCgyWwlTBpIhbhfgHeFMmKVEFg3LBfvVd5OXVQ="
	servingRRSIG  = servingTestZone + " 300 IN RRSIG DNSKEY 15 2 300 20300101000000 20200101000000 1 " + servingTestZone + " c2lnbmF0dXJl"
	servingSOA    = servingTestZone + " 300 IN SOA ns1.asked.example. hostmaster.asked.example. 1 3600 600 86400 300"
	servingAbove  = "example. 300 IN SOA ns.example. hostmaster.example. 1 3600 600 86400 300"
	servingOther  = "other.example. 300 IN SOA ns.other.example. hostmaster.other.example. 1 3600 600 86400 300"
	servingNS     = servingTestZone + " 300 IN NS ns1.elsewhere.example."
	servingDS     = servingTestZone + " 300 IN DS 1 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	servingNSECed = servingTestZone + " 300 IN NSEC a.asked.example. SOA NS RRSIG NSEC"
)

func servingKeys(q *dns.Msg) *dns.Msg {
	r := servingReply(q, dns.RcodeSuccess, []string{servingKSK, servingZSK, servingRRSIG}, nil)
	r.Authoritative = true
	return r
}

// truncatedOf is r as a server sends it that cannot fit it: the flag, and what fits.
func truncatedOf(r *dns.Msg, fits int) *dns.Msg {
	r.Truncated = true
	r.Answer = r.Answer[:fits]
	return r
}

// What a look reads from each answer a nameserver can give, from the bytes on the wire.
func TestAskServingReadsWhatANameserverAnswers(t *testing.T) {
	const (
		serves = iota
		noRRset
		saysNothing
	)
	for _, c := range []struct {
		name    string
		noTCP   bool
		answer  func(q *dns.Msg, overTCP bool) *dns.Msg
		want    int
		wantErr string
	}{
		{name: "the keys", want: serves, answer: func(q *dns.Msg, _ bool) *dns.Msg { return servingKeys(q) }},
		{name: "NODATA", want: noRRset, answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeSuccess, nil, []string{servingSOA})
		}},
		{name: "NODATA of a signed zone", want: noRRset, answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeSuccess, nil, []string{servingNSECed, servingSOA})
		}},
		{name: "NODATA with the zone's NS beside the SOA", want: noRRset, answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeSuccess, nil, []string{servingNS, servingSOA})
		}},
		{name: "NODATA under the SOA of a zone above", want: noRRset, answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeSuccess, nil, []string{servingAbove})
		}},
		{name: "NOERROR and nothing at all", want: noRRset, answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeSuccess, nil, nil)
		}},
		{name: "another type in the answer", want: noRRset, answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeSuccess, []string{servingNS}, nil)
		}},
		{name: "NXDOMAIN with a SOA", want: noRRset, answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeNameError, nil, []string{servingAbove})
		}},
		{name: "NXDOMAIN with no SOA", want: saysNothing, wantErr: "NXDOMAIN with no SOA", answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeNameError, nil, nil)
		}},
		{name: "a referral", want: saysNothing, wantErr: "a referral", answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeSuccess, nil, []string{servingNS, servingDS})
		}},
		{name: "an authority with only another zone's SOA", want: saysNothing, wantErr: "a referral", answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeSuccess, nil, []string{servingOther})
		}},
		{name: "REFUSED", want: saysNothing, wantErr: "REFUSED", answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeRefused, nil, nil)
		}},
		{name: "SERVFAIL", want: saysNothing, wantErr: "SERVFAIL", answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeServerFailure, nil, nil)
		}},
		{name: "a reply to another question", want: saysNothing, wantErr: "another question", answer: func(q *dns.Msg, _ bool) *dns.Msg {
			r := servingKeys(q)
			r.Question[0].Name = "other.example."
			return r
		}},
		{name: "truncated with nothing, whole over TCP", want: serves, answer: func(q *dns.Msg, overTCP bool) *dns.Msg {
			if overTCP {
				return servingKeys(q)
			}
			return truncatedOf(servingKeys(q), 0)
		}},
		{name: "truncated with part of the keys, whole over TCP", want: serves, answer: func(q *dns.Msg, overTCP bool) *dns.Msg {
			if overTCP {
				return servingKeys(q)
			}
			return truncatedOf(servingKeys(q), 1)
		}},
		{name: "truncated, and NODATA over TCP", want: noRRset, answer: func(q *dns.Msg, overTCP bool) *dns.Msg {
			if overTCP {
				return servingReply(q, dns.RcodeSuccess, nil, []string{servingSOA})
			}
			return truncatedOf(servingKeys(q), 0)
		}},
		{name: "truncated, and no TCP", noTCP: true, want: saysNothing, wantErr: "truncated", answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return truncatedOf(servingKeys(q), 0)
		}},
		{name: "truncated over TCP as well", want: saysNothing, wantErr: "truncated", answer: func(q *dns.Msg, _ bool) *dns.Msg {
			return truncatedOf(servingKeys(q), 1)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr := servingListener(t, !c.noTCP, c.answer)
			rrset, err := askServing(context.Background(), servingTestZone, dns.TypeDNSKEY, []string{addr})
			switch c.want {
			case serves:
				if err != nil {
					t.Fatalf("got error %v, want the keys", err)
				}
				if len(rrset.RRs) != 2 || len(rrset.RRSIGs) != 1 {
					t.Fatalf("got %d keys and %d signatures, want 2 and 1", len(rrset.RRs), len(rrset.RRSIGs))
				}
			case noRRset:
				if !errors.Is(err, errServesNoRRset) {
					t.Fatalf("got %v, %v, want errServesNoRRset", rrset, err)
				}
			case saysNothing:
				if err == nil || errors.Is(err, errServesNoRRset) || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("got %v, %v, want an error naming %q that is not errServesNoRRset", rrset, err, c.wantErr)
				}
			}
		})
	}
}

// An address that says nothing leaves the next to be asked; one that answers for the
// name ends it, as both are the same nameserver.
func TestAskServingAsksOnUntilAnAddressAnswers(t *testing.T) {
	refuses := servingListener(t, true, func(q *dns.Msg, _ bool) *dns.Msg { return servingReply(q, dns.RcodeRefused, nil, nil) })
	noData := servingListener(t, true, func(q *dns.Msg, _ bool) *dns.Msg {
		return servingReply(q, dns.RcodeSuccess, nil, []string{servingSOA})
	})
	keys := servingListener(t, true, func(q *dns.Msg, _ bool) *dns.Msg { return servingKeys(q) })
	if rrset, err := askServing(context.Background(), servingTestZone, dns.TypeDNSKEY, []string{refuses, keys}); err != nil || len(rrset.RRs) != 2 {
		t.Errorf("REFUSED, then the keys: got %v, %v", rrset, err)
	}
	if _, err := askServing(context.Background(), servingTestZone, dns.TypeDNSKEY, []string{noData, keys}); !errors.Is(err, errServesNoRRset) {
		t.Errorf("NODATA, then the keys: got %v, want errServesNoRRset", err)
	}
	if _, err := askServing(context.Background(), servingTestZone, dns.TypeDNSKEY, nil); err == nil || errors.Is(err, errServesNoRRset) {
		t.Errorf("no address: got %v, want an error that says nothing", err)
	}
}

// The look as the keys' step reads it, from real answers: what the wire says decides
// whether the step holds. The step's own tests stub the lookup; this is what joins them.
func TestAJoinersKeysStepReadsWhatTheWireSays(t *testing.T) {
	keysReply := func(w *keysWait, q *dns.Msg) *dns.Msg {
		r := new(dns.Msg)
		r.SetReply(q)
		for _, k := range []*dns.DNSKEY{w.ksk, w.zsk} {
			c := *k
			c.Hdr.Ttl = 300
			r.Answer = append(r.Answer, &c)
		}
		return r
	}
	ask := func(w *keysWait, ns, addr string) {
		w.answers[ns] = func() (*core.RRset, error) {
			return askServing(context.Background(), w.r.zone, dns.TypeDNSKEY, []string{addr})
		}
	}
	serving := func(t *testing.T, w *keysWait) {
		ask(w, keysNS1, servingListener(t, true, func(q *dns.Msg, _ bool) *dns.Msg { return keysReply(w, q) }))
	}
	t.Run("NODATA holds", func(t *testing.T) {
		w := newKeysWait(t, "wire-nodata.keys.adding.example.")
		serving(t, w)
		ask(w, keysNS2, servingListener(t, true, func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeSuccess, nil, []string{w.r.zone + " 300 IN SOA ns1. h. 1 3600 600 86400 300"})
		}))
		if got := w.look(); !strings.Contains(got, keysNS2) {
			t.Fatalf("it waits for %q, want ns2", got)
		}
		if got := w.after(24 * time.Hour); !strings.Contains(got, keysNS2) {
			t.Fatalf("a day on, it waits for %q, want ns2", got)
		}
	})
	t.Run("a copy without the keys holds", func(t *testing.T) {
		w := newKeysWait(t, "wire-stale.keys.adding.example.")
		serving(t, w)
		other := testDnskey(t, w.r.zone, 257)
		ask(w, keysNS2, servingListener(t, true, func(q *dns.Msg, _ bool) *dns.Msg {
			r := new(dns.Msg)
			r.SetReply(q)
			r.Answer = []dns.RR{other}
			return r
		}))
		if got := w.after(24 * time.Hour); !strings.Contains(got, keysNS2) {
			t.Fatalf("a day on, it waits for %q, want ns2", got)
		}
	})
	t.Run("a referral does not hold, and the copy's TTL is the floor", func(t *testing.T) {
		w := newKeysWait(t, "wire-referral.keys.adding.example.")
		w.copyHasDNSKEY(time.Hour)
		serving(t, w)
		ask(w, keysNS2, servingListener(t, true, func(q *dns.Msg, _ bool) *dns.Msg {
			return servingReply(q, dns.RcodeSuccess, nil, []string{w.r.zone + " 300 IN NS ns1.elsewhere.example."})
		}))
		if got := w.look(); got == "" || strings.Contains(got, keysNS2) {
			t.Fatalf("it waits for %q, want the TTL and not ns2", got)
		}
		if got := w.after(time.Hour - time.Second); got == "" {
			t.Error("short of its copy's TTL, nothing is waited for")
		}
		if got := w.after(time.Second); got != "" {
			t.Errorf("past its copy's TTL, it waits for %q", got)
		}
	})
	t.Run("a truncated reply with the keys over TCP does not hold", func(t *testing.T) {
		w := newKeysWait(t, "wire-tcp.keys.adding.example.")
		serving(t, w)
		ask(w, keysNS2, servingListener(t, true, func(q *dns.Msg, overTCP bool) *dns.Msg {
			if overTCP {
				return keysReply(w, q)
			}
			return truncatedOf(keysReply(w, q), 0)
		}))
		if got := w.look(); got == "" || strings.Contains(got, keysNS2) {
			t.Fatalf("it waits for %q, want the TTL and not ns2", got)
		}
		if got := w.after(5 * time.Minute); got != "" {
			t.Errorf("both serve them and their TTL has passed, and it waits for %q", got)
		}
	})
	t.Run("a truncated reply and no TCP is silence, and does not hold", func(t *testing.T) {
		w := newKeysWait(t, "wire-notcp.keys.adding.example.")
		w.copyHasDNSKEY(time.Hour)
		serving(t, w)
		ask(w, keysNS2, servingListener(t, false, func(q *dns.Msg, _ bool) *dns.Msg {
			return truncatedOf(keysReply(w, q), 0)
		}))
		if got := w.look(); got == "" || strings.Contains(got, keysNS2) {
			t.Fatalf("it waits for %q, want the TTL and not ns2", got)
		}
		if got := w.after(time.Hour); got != "" {
			t.Errorf("past its copy's TTL, it waits for %q", got)
		}
	})
}
