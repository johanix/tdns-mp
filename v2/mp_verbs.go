/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The application verb table (transport redesign, Stage C3).
 *
 * ONE table drives both sides of the receive path:
 *
 *   - RegisterAppVerbs registers each application verb's handler on the
 *     router for the roles that accept it (what InitializeRouter,
 *     InitializeCombinerRouter and InitializeSignerRouter used to do in
 *     tdns-transport), and
 *   - routeIncomingMessage dispatches the RouteToCallback delivery to the
 *     verb's MP route function (what the old switch in hsync_transport.go
 *     did).
 *
 * Transport-own verbs (hello, beat, ping, confirm) are registered by
 * transport.InitializeRouter; they appear here only for their MP-side
 * consumers. The dispatch gate (transport_dispatch_test.go) exercises
 * every row through the real router.
 */

package tdnsmp

import (
	"github.com/johanix/tdns-transport/v2/transport"
)

const (
	roleAgent    = "agent"
	roleAuditor  = "auditor"
	roleSigner   = "signer"
	roleCombiner = "combiner"
)

type appVerb struct {
	token string
	// roles that register handle on their router. Empty for transport-own
	// verbs (registered by transport.InitializeRouter).
	roles []string
	// handle validates the payload, stores the parsed message for the
	// RouteToCallback seam and prepares the inline confirmation. nil for
	// transport-own verbs.
	handle func(tm *MPTransportBridge, ctx *transport.MessageContext) error
	// route is the MP-side consumer invoked by RouteToCallback after the
	// handler ran. nil when transport handles the verb completely.
	route func(tm *MPTransportBridge, msg *transport.IncomingMessage)
	desc  string
}

var (
	rolesAll        = []string{roleAgent, roleAuditor, roleSigner, roleCombiner}
	rolesAgentLike  = []string{roleAgent, roleAuditor}
	rolesKeystate   = []string{roleAgent, roleAuditor, roleSigner}
	rolesCombiner   = []string{roleCombiner}
	appVerbRegistry = appVerbTable()
)

func appVerbTable() []appVerb {
	return []appVerb{
		// transport-own verbs; MP only consumes them.
		{token: "hello", route: (*MPTransportBridge).routeHelloMessage},
		{token: "beat", route: (*MPTransportBridge).routeBeatMessage},
		{token: "ping", route: (*MPTransportBridge).routePingMessage},
		{token: "confirm"}, // fully handled by transport (HandleConfirmation → OnConfirmationReceived)

		// application verbs.
		{token: "sync", roles: rolesAgentLike, handle: handleAppSync,
			route: (*MPTransportBridge).routeSyncMessage,
			desc:  "Processes zone synchronization messages"},
		{token: "update", roles: rolesCombiner, handle: combinerUpdateHandler(),
			route: (*MPTransportBridge).routeSyncMessage,
			desc:  "Combiner: processes zone update contributions from agents"},
		{token: "rfi", roles: rolesAll, handle: handleAppRfi,
			route: (*MPTransportBridge).routeSyncMessage,
			desc:  "Processes RFI (Request For Information) messages"},
		{token: "keystate", roles: rolesKeystate, handle: handleAppKeystate,
			route: (*MPTransportBridge).routeKeystateMessage,
			desc:  "Processes KEYSTATE messages for key lifecycle signaling"},
		{token: "edits", roles: rolesAgentLike, handle: handleAppEdits,
			route: (*MPTransportBridge).routeEditsMessage,
			desc:  "Processes EDITS messages with agent contributions from combiner"},
		{token: "config", roles: rolesAgentLike, handle: handleAppConfig,
			route: (*MPTransportBridge).routeConfigMessage,
			desc:  "Processes CONFIG response messages from peer agents"},
		{token: "audit", roles: rolesAgentLike, handle: handleAppAudit,
			route: (*MPTransportBridge).routeAuditMessage,
			desc:  "Processes AUDIT response messages from peer agents"},
		{token: "status-update", roles: rolesAll, handle: handleAppStatusUpdate,
			route: (*MPTransportBridge).routeStatusUpdateMessage,
			desc:  "Processes STATUS-UPDATE messages for delegation change notifications"},
		{token: "relocate", roles: rolesAgentLike, handle: handleAppRelocate,
			route: (*MPTransportBridge).routeRelocateMessage,
			desc:  "Processes relocate messages for DDoS mitigation"},
	}
}

func roleAccepts(v *appVerb, role string) bool {
	for _, r := range v.roles {
		if r == role {
			return true
		}
	}
	return false
}

// RegisterAppVerbs registers this role's application verb handlers on the
// router, after transport.InitializeRouter has installed the middleware
// chain and the transport-own handlers.
func (tm *MPTransportBridge) RegisterAppVerbs(router *transport.DNSMessageRouter, role string) error {
	if router == nil {
		return nil
	}
	n := 0
	for i := range appVerbRegistry {
		v := &appVerbRegistry[i]
		if v.handle == nil || !roleAccepts(v, role) {
			continue
		}
		handle := v.handle
		if err := router.Register(v.token+"-handler", transport.MessageType(v.token),
			func(ctx *transport.MessageContext) error { return handle(tm, ctx) },
			transport.WithPriority(100), transport.WithDescription(v.desc)); err != nil {
			return err
		}
		n++
	}
	lgTransport.Info("registered application verbs", "role", role, "count", n)
	return nil
}

// routeIncomingMessage is the RouteToCallback callback: it hands a
// successfully handled message to the verb's MP consumer.
func (tm *MPTransportBridge) routeIncomingMessage(msg *transport.IncomingMessage) {
	token := msg.Token()
	lgTransport.Debug("routing message", "type", token, "sender", msg.SenderID)
	for i := range appVerbRegistry {
		v := &appVerbRegistry[i]
		if v.token != token {
			continue
		}
		if v.route != nil {
			v.route(tm, msg)
		}
		return
	}
	lgTransport.Warn("unknown message type", "type", token)
}

// combinerUpdateHandler adapts the combiner's pending-ack update handler
// (combiner_chunk.go) to the table's handler shape.
func combinerUpdateHandler() func(*MPTransportBridge, *transport.MessageContext) error {
	h := NewCombinerSyncHandler()
	return func(_ *MPTransportBridge, ctx *transport.MessageContext) error { return h(ctx) }
}
