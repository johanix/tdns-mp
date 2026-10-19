/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The hand-over of a zone's SIG(0) key by a provider whose role the owner has
 * taken: what the two agents let in, and what the new leader takes.
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

// The provider that led the zone, C, holds the key and has no role in the
// zone now. Admission let a message about a zone in only between two of its
// role holders, so C refused the new leader's request for the key, while C
// and A share another zone in which both still hold roles. C lets a request
// about the zone in from a voting member, and only the request for the key
// gets through. A message about the other zone is as before.
func TestTheProviderThatLedLetsInTheRequestForTheKeyOnly(t *testing.T) {
	moved, other := handoverZones(t)
	c := handoverBridge(arrivalC)

	if ok, reason := c.IsPeerAuthorized(arrivalA, string(moved)); !ok {
		t.Fatalf("C refuses A's message about %s: %s", moved, reason)
	}
	if !c.keyHandOverOnly(rfiMessage(t, arrivalA, moved, "sig0key")) {
		t.Error("C does not act on A's request for the key of the zone that moved")
	}
	if c.keyHandOverOnly(rfiMessage(t, arrivalA, moved, "upstream")) {
		t.Error("C acts on another request from A about the zone it has no role in")
	}
	if ok, _ := c.IsPeerAuthorized(arrivalA, string(other)); !ok || !c.keyHandOverOnly(rfiMessage(t, arrivalA, other, "upstream")) {
		t.Error("C no longer takes A's messages about the zone in which both hold roles")
	}

	// A sender with no vote in the zone may not hold the key, and is let in
	// for nothing.
	d := handoverBridge(arrivalC)
	if ok, _ := d.IsPeerAuthorized("stranger.agent.example.", string(moved)); ok {
		t.Error("C lets in a sender that has no role in the zone")
	}
}

// The new leader, A, asked C for the key. C has no role in the zone, and its
// answer was refused at A. A lets it in while its request is out, and only
// the answer about the key gets through.
func TestTheNewLeaderLetsInTheAnswerToItsRequestOnly(t *testing.T) {
	moved, _ := handoverZones(t)
	a := handoverBridge(arrivalA)

	if ok, _ := a.IsPeerAuthorized(arrivalC, string(moved)); ok {
		t.Fatal("A lets C in about the zone with no request out: the test shows nothing")
	}
	done := a.keyAsks.start(arrivalC, string(moved))
	if ok, reason := a.IsPeerAuthorized(arrivalC, string(moved)); !ok {
		t.Fatalf("A refuses C's answer to its request for the key: %s", reason)
	}
	if !a.keyHandOverOnly(configMessage(t, arrivalC, moved, "sig0key")) {
		t.Error("A does not act on C's answer about the key")
	}
	if a.keyHandOverOnly(configMessage(t, arrivalC, moved, "upstream")) {
		t.Error("A acts on another answer from C about the zone C has no role in")
	}
	done()
	if ok, _ := a.IsPeerAuthorized(arrivalC, string(moved)); ok {
		t.Error("A still lets C in once its request is over")
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
// acknowledged it as taken. The request for the key does.
func TestAMessageLetInForTheKeyAloneReachesNoHandlerUnlessItIsAboutTheKey(t *testing.T) {
	moved, _ := handoverZones(t)
	c := handoverBridge(arrivalC)
	reached := func(msg *transport.IncomingMessage) bool {
		ctx := &transport.MessageContext{Data: map[string]interface{}{}}
		ctx.SetIncoming(msg)
		handled := false
		_ = c.keyHandOverGate(ctx, func(*transport.MessageContext) error { handled = true; return nil })
		return handled
	}
	if !reached(rfiMessage(t, arrivalA, moved, "sig0key")) {
		t.Error("A's request for the key does not reach C's handler")
	}
	if reached(rfiMessage(t, arrivalA, moved, "upstream")) {
		t.Error("another request from A about the zone C has no role in reaches C's handler")
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
	if reached(confirm(arrivalA, "other-distribution")) {
		t.Error("a confirmation of another distribution reaches C's transport")
	}
	c.keyAsks.expectConfirm(arrivalA, "key-answer")
	if !reached(confirm(arrivalA, "key-answer")) {
		t.Error("A's confirmation of C's answer about the key does not reach C's transport")
	}
	if reached(confirm(arrivalB, "key-answer")) {
		t.Error("B's confirmation of the answer C sent to A reaches C's transport")
	}
}

// An RFI is routed by its payload's MessageType, and one with none is taken
// as a sync, whose records and operations are applied. Such a message, sent
// as an RFI with the key's markers, passed the check for the key alone and
// reached the update path. Only a payload that says rfi itself, and carries
// nothing to apply, is the request for the key.
func TestARequestForTheKeyThatCarriesAnUpdateIsRefused(t *testing.T) {
	moved, _ := handoverZones(t)
	c := handoverBridge(arrivalC)
	send := func(p *DnsSyncPayload) bool {
		payload, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("payload: %v", err)
		}
		return c.keyHandOverOnly(&transport.IncomingMessage{TypeToken: "rfi", SenderID: arrivalA, TransportSender: arrivalA, Zone: string(moved), Payload: payload})
	}
	key := func() *DnsSyncPayload {
		return &DnsSyncPayload{MessageType: "rfi", OriginatorID: arrivalA, Zone: string(moved), RfiType: "CONFIG", RfiSubtype: "sig0key"}
	}
	if !send(key()) {
		t.Fatal("the request for the key is refused")
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
