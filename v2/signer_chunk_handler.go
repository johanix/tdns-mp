/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Signer CHUNK handler registration.
 * Extracted from tdns/v2/combiner_chunk.go.
 */
package tdnsmp

import (
	"context"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

// RegisterSignerChunkHandler creates a ChunkNotifyHandler for the signer role
// and registers it to handle incoming CHUNK NOTIFY messages.
func RegisterSignerChunkHandler(localID string, secureWrapper *transport.SecurePayloadWrapper) (*CombinerState, error) {
	state := &CombinerState{
		ErrorJournal: NewErrorJournal(100, 24*time.Hour),
	}

	handler := &transport.ChunkNotifyHandler{
		ParseApp:      parseAppPayload, // C5: the application parses its own payloads
		LocalID:       localID,
		Router:        nil, // Set after router initialization via SetRouter()
		SecureWrapper: secureWrapper,
	}

	err := tdns.RegisterNotifyHandler(core.TypeCHUNK, func(ctx context.Context, req *tdns.DnsNotifyRequest) error {
		return handler.RouteViaRouter(ctx, req.Qname, req.Msg, req.ResponseWriter)
	})
	if err != nil {
		return nil, err
	}

	state.ChunkNotifyHandler = handler

	return state, nil
}
