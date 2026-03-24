/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Signer CHUNK handler registration.
 * Extracted from tdns/v2/combiner_chunk.go.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// RegisterSignerChunkHandler creates a ChunkNotifyHandler for the signer role
// and registers it to handle incoming CHUNK NOTIFY messages.
func RegisterSignerChunkHandler(localID string, secureWrapper *transport.SecurePayloadWrapper) (*tdns.CombinerState, error) {
	state := &tdns.CombinerState{
		ErrorJournal: tdns.NewErrorJournal(100, 24*time.Hour),
	}

	handler := &transport.ChunkNotifyHandler{
		LocalID:       localID,
		Router:        nil, // Set after router initialization via SetRouter()
		SecureWrapper: secureWrapper,
		IncomingChan:  make(chan *transport.IncomingMessage, 100),
	}

	// Wire FetchChunkQuery for chunk_mode=query (signer has no DNSTransport)
	handler.FetchChunkQuery = fetchChunkPayloadViaQuery

	err := tdns.RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *tdns.DnsNotifyRequest) error {
		return handler.RouteViaRouter(ctx, req.Qname, req.Msg, req.ResponseWriter)
	})
	if err != nil {
		return nil, err
	}

	// TODO: needs tdns wrapper — chunkHandler is unexported
	// state.chunkHandler = handler
	tdns.CombinerStateSetChunkHandler(state, handler)

	return state, nil
}

// fetchChunkPayloadViaQuery queries a DNS server for a CHUNK RR.
// Used as the FetchChunkQuery callback for the signer ChunkNotifyHandler.
func fetchChunkPayloadViaQuery(ctx context.Context, serverAddr, qname string) ([]byte, error) {
	if host, port, err := net.SplitHostPort(serverAddr); err != nil {
		if host != "" {
			serverAddr = net.JoinHostPort(host, "53")
		} else {
			serverAddr = net.JoinHostPort(serverAddr, "53")
		}
	} else if port == "" {
		serverAddr = net.JoinHostPort(host, "53")
	}

	m := new(dns.Msg)
	q := dns.Fqdn(qname)
	m.SetQuestion(q, core.TypeCHUNK)
	m.RecursionDesired = false

	c := &dns.Client{Timeout: 5 * time.Second, Net: "tcp"}
	in, _, err := c.ExchangeContext(ctx, m, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("CHUNK query %s to %s failed: %w", qname, serverAddr, err)
	}
	if in == nil || in.Rcode != dns.RcodeSuccess {
		rcode := dns.RcodeSuccess
		if in != nil {
			rcode = in.Rcode
		}
		return nil, fmt.Errorf("CHUNK query %s to %s returned rcode %s", qname, serverAddr, dns.RcodeToString[rcode])
	}
	for _, rr := range in.Answer {
		if prr, ok := rr.(*dns.PrivateRR); ok && prr.Hdr.Rrtype == core.TypeCHUNK {
			if chunk, ok := prr.Data.(*core.CHUNK); ok && chunk != nil {
				return chunk.Data, nil
			}
		}
	}
	return nil, fmt.Errorf("no CHUNK RR in response from %s for qname %s", serverAddr, qname)
}
