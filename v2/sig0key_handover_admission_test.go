/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The hand-over of a zone's SIG(0) key: what the agents let in, and what the
 * new leader takes. From the switch (plan S15) a provider whose role the
 * owner has taken and whose record stays is a member, admitted in full; the
 * gate for the key alone lets in the answer of an agent asked that is no
 * member of the zone here.
 */
package tdnsmp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// handoverBridge is an agent's transport, as admission sees it: its identity
// and the zones it holds.
func handoverBridge(local string) *MPTransportBridge {
	return &MPTransportBridge{
		TransportManager: &transport.TransportManager{LocalID: local},
		getZone:          func(name string) (*tdns.ZoneData, bool) { return tdns.Zones.Get(name) },
	}
}

// handoverZones are two zones that A, B and C share. In the zone that moved
// the owner has taken C's role and kept its HSYNC3 record. In the other they
// all keep theirs, so C is no LEGACY peer of A's: they share a zone.
func handoverZones(t *testing.T) (moved, other ZoneName) {
	t.Helper()
	mz := providerZone(t, "moved.handover.example.", arrivalA, arrivalB, arrivalC)
	zoneEdit{listed: []string{arrivalA, arrivalB, arrivalC}, serving: []string{arrivalA, arrivalB}}.apply(t, mz)
	oz := providerZone(t, "other.handover.example.", arrivalA, arrivalB, arrivalC)
	return ZoneName(mz.ZoneName), ZoneName(oz.ZoneName)
}

func rfiMessage(t *testing.T, sender string, zone ZoneName, subtype string) *transport.IncomingMessage {
	t.Helper()
	payload, err := json.Marshal(&DnsSyncPayload{MessageType: "rfi", OriginatorID: sender, Zone: string(zone), RfiType: "CONFIG", RfiSubtype: subtype})
	if err != nil {
		t.Fatalf("rfi payload: %v", err)
	}
	return &transport.IncomingMessage{TypeToken: "rfi", SenderID: sender, TransportSender: sender, Zone: string(zone), Payload: payload}
}

func configMessage(t *testing.T, sender string, zone ZoneName, subtype string) *transport.IncomingMessage {
	t.Helper()
	payload, err := json.Marshal(&DnsConfigPayload{MessageType: "config", Zone: string(zone), Subtype: subtype})
	if err != nil {
		t.Fatalf("config payload: %v", err)
	}
	return &transport.IncomingMessage{TypeToken: "config", SenderID: sender, TransportSender: sender, Zone: string(zone), Payload: payload}
}

// handoverStranger is no member of the zone that moved: a voting member
// under the zone's other serial, say, whom the new leader asks for the key
// (transitionVoters, plan S14).
const handoverStranger = "d.agent.example."

// The provider that led the zone, C, holds the key and has no role in the
// zone now. From the switch (plan S15) it is a member: it admits the new
// leader's messages about the zone in full, its request for the key and any
// other, and the new leader admits C's. A sender that is no member is let in
// for nothing.
func TestAMemberWithNoRoleIsAdmittedInFull(t *testing.T) {
	moved, other := handoverZones(t)
	c, a := handoverBridge(arrivalC), handoverBridge(arrivalA)

	if ok, reason := c.IsPeerAuthorized(arrivalA, string(moved)); !ok {
		t.Fatalf("C refuses A's message about %s: %s", moved, reason)
	}
	for _, subtype := range []string{"sig0key", "upstream"} {
		if !c.keyHandOverOnly(rfiMessage(t, arrivalA, moved, subtype)) {
			t.Errorf("C does not act on A's %s request about the zone it is a member of with no role", subtype)
		}
	}
	if ok, reason := a.IsPeerAuthorized(arrivalC, string(moved)); !ok {
		t.Errorf("A refuses C's message about %s with no request out: %s", moved, reason)
	}
	if ok, _ := c.IsPeerAuthorized(arrivalA, string(other)); !ok || !c.keyHandOverOnly(rfiMessage(t, arrivalA, other, "upstream")) {
		t.Error("C no longer takes A's messages about the zone in which both hold roles")
	}
	if ok, _ := c.IsPeerAuthorized(handoverStranger, string(moved)); ok {
		t.Error("C lets in a sender that is no member of the zone")
	}
}

// The new leader, A, asked an agent that is no member of the zone here for
// the key. A lets its answer in while its request is out, and only the
// answer about the key gets through.
func TestTheNewLeaderLetsInTheAnswerToItsRequestOnly(t *testing.T) {
	moved, _ := handoverZones(t)
	a := handoverBridge(arrivalA)

	if ok, _ := a.IsPeerAuthorized(handoverStranger, string(moved)); ok {
		t.Fatal("A lets the stranger in about the zone with no request out: the test shows nothing")
	}
	done := a.keyAsks.start(handoverStranger, string(moved))
	if ok, reason := a.IsPeerAuthorized(handoverStranger, string(moved)); !ok {
		t.Fatalf("A refuses the answer to its request for the key: %s", reason)
	}
	if !a.keyHandOverOnly(configMessage(t, handoverStranger, moved, "sig0key")) {
		t.Error("A does not act on the answer about the key")
	}
	if a.keyHandOverOnly(configMessage(t, handoverStranger, moved, "upstream")) {
		t.Error("A acts on another answer from an agent that is no member of the zone")
	}
	done()
	if ok, _ := a.IsPeerAuthorized(handoverStranger, string(moved)); ok {
		t.Error("A still lets the stranger in once its request is over")
	}
}

// A handed-over key is taken only when the zone publishes it, or publishes no
// KEY at all: one the zone does not publish would put a key the parent does
// not know in place of the one it trusts.
func TestAHandedOverKeyIsTakenOnlyWhenTheZonePublishesIt(t *testing.T) {
	zd := providerZone(t, "published.handover.example.", arrivalA, arrivalB)
	zone := ZoneName(zd.ZoneName)
	published, _ := newSig0Key(t, zd.ZoneName)
	other, otherPEM := newSig0Key(t, zd.ZoneName)

	if !zoneTakesKey(zone, other) {
		t.Fatal("a zone that publishes no KEY refuses a handed-over key")
	}
	apex, _ := zd.Data.Get(zd.ZoneName)
	apex.RRtypes.Set(dns.TypeKEY, core.RRset{Name: zd.ZoneName, RRtype: dns.TypeKEY, Class: dns.ClassINET, RRs: []dns.RR{published}})
	zd.Data.Set(zd.ZoneName, apex)
	zd.InstallInitialSnapshot()

	if !zoneTakesKey(zone, published) {
		t.Error("the zone refuses the key it publishes")
	}
	if zoneTakesKey(zone, other) {
		t.Error("the zone takes a key it does not publish")
	}
	// hdb is nil: the refusal comes before the keystore is touched.
	err := importSig0KeyFromPeer(nil, zd.ZoneName, map[string]string{"algorithm": "ED25519", "privatekey": otherPEM, "keyrr": other.String()})
	if err == nil || !strings.Contains(err.Error(), "does not publish") {
		t.Errorf("the import of a key the zone does not publish: err = %v, want a refusal", err)
	}
}

// The check runs before the verb handlers: a message let in for the key
// alone that is not about the key reaches no handler, which would have
// acknowledged it as taken. The answer about the key does.
func TestAMessageLetInForTheKeyAloneReachesNoHandlerUnlessItIsAboutTheKey(t *testing.T) {
	moved, _ := handoverZones(t)
	a := handoverBridge(arrivalA)
	defer a.keyAsks.start(handoverStranger, string(moved))()
	reached := func(msg *transport.IncomingMessage) bool {
		ctx := &transport.MessageContext{Data: map[string]interface{}{}}
		ctx.SetIncoming(msg)
		handled := false
		_ = a.keyHandOverGate(ctx, func(*transport.MessageContext) error { handled = true; return nil })
		return handled
	}
	if !reached(configMessage(t, handoverStranger, moved, "sig0key")) {
		t.Error("the answer about the key does not reach A's handler")
	}
	if reached(configMessage(t, handoverStranger, moved, "upstream")) {
		t.Error("another answer from an agent that is no member reaches A's handler")
	}
	// A delivery confirmation reaches the transport's own handler, which
	// settles the sender's queued message, only when it confirms the key
	// exchange's own message, sent to that peer. Any other confirmation
	// would settle another distribution.
	confirm := func(sender, id string) *transport.IncomingMessage {
		payload, err := json.Marshal(&transport.DnsConfirmPayload{Type: "confirm", SenderID: sender, Zone: string(moved), DistributionID: id})
		if err != nil {
			t.Fatalf("confirm payload: %v", err)
		}
		return &transport.IncomingMessage{TypeToken: "confirm", SenderID: sender, TransportSender: sender, Zone: string(moved), Payload: payload}
	}
	if reached(confirm(handoverStranger, "other-distribution")) {
		t.Error("a confirmation of another distribution reaches A's transport")
	}
	a.keyAsks.expectConfirm(handoverStranger, "key-request")
	if !reached(confirm(handoverStranger, "key-request")) {
		t.Error("the confirmation of A's request for the key does not reach A's transport")
	}
}

// The gate's refusal is REFUSED on the wire and no handler error: the
// router logs a handler error, and a message refused by the rule is no
// failure of this agent's. The answer about the key gets no rcode from the
// gate.
func TestTheKeyGatesRefusalIsNoHandlerError(t *testing.T) {
	moved, _ := handoverZones(t)
	a := handoverBridge(arrivalA)
	defer a.keyAsks.start(handoverStranger, string(moved))()
	gate := func(msg *transport.IncomingMessage) (*transport.MessageContext, bool, error) {
		ctx := &transport.MessageContext{Data: map[string]interface{}{}}
		ctx.SetIncoming(msg)
		handled := false
		err := a.keyHandOverGate(ctx, func(*transport.MessageContext) error { handled = true; return nil })
		return ctx, handled, err
	}
	rcode := func(ctx *transport.MessageContext) (int, bool) {
		rc, ok := ctx.Data["response_rcode"].(int)
		return rc, ok
	}
	ctx, handled, err := gate(configMessage(t, handoverStranger, moved, "upstream"))
	if err != nil {
		t.Errorf("the refusal is a handler error: %v", err)
	}
	if rc, _ := rcode(ctx); rc != dns.RcodeRefused || handled {
		t.Errorf("another answer: rcode %d, handled %v; want REFUSED and no handler", rc, handled)
	}
	ctx, handled, err = gate(configMessage(t, handoverStranger, moved, "sig0key"))
	if _, set := rcode(ctx); err != nil || set || !handled {
		t.Errorf("the answer about the key: err %v, rcode set %v, handled %v", err, set, handled)
	}
}

// Only an agent this agent asked is let in for the key alone, and only its
// answer and confirmations get through: an RFI from it is refused, the
// request for the key and one that carries an update alike (plan S15).
func TestARequestFromAnAgentLetInForTheKeyAloneIsRefused(t *testing.T) {
	moved, _ := handoverZones(t)
	a := handoverBridge(arrivalA)
	defer a.keyAsks.start(handoverStranger, string(moved))()
	send := func(p *DnsSyncPayload) bool {
		payload, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("payload: %v", err)
		}
		return a.keyHandOverOnly(&transport.IncomingMessage{TypeToken: "rfi", SenderID: handoverStranger, TransportSender: handoverStranger, Zone: string(moved), Payload: payload})
	}
	key := func() *DnsSyncPayload {
		return &DnsSyncPayload{MessageType: "rfi", OriginatorID: handoverStranger, Zone: string(moved), RfiType: "CONFIG", RfiSubtype: "sig0key"}
	}
	if send(key()) {
		t.Error("a request for the key from an agent let in for the key alone is let through")
	}
	untyped := key()
	untyped.MessageType = ""
	if send(untyped) {
		t.Error("a request for the key with no MessageType, routed as a sync, is let through")
	}
	withRecords := key()
	withRecords.Records = map[string][]string{string(moved): {string(moved) + " 3600 IN NS ns.other.example."}}
	if send(withRecords) {
		t.Error("a request for the key that carries records is let through")
	}
}
