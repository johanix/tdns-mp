/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"fmt"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Two Ed25519 public keys (RFC 8080's examples): a KSK and a ZSK.
const (
	testKSKPub = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
	testZSKPub = "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs="
)

func testDNSKEY(t *testing.T, flags uint16, pub string) (string, uint16) {
	t.Helper()
	rr, err := dns.NewRR(fmt.Sprintf("example.com. 3600 IN DNSKEY %d 3 15 %s", flags, pub))
	if err != nil {
		t.Fatalf("DNSKEY: %v", err)
	}
	return rr.String(), rr.(*dns.DNSKEY).KeyTag()
}

func boolp(b bool) *bool { return &b }

func wantLines(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("description lacks %q; it is:\n%s", w, got)
		}
	}
}

// A DNSKEY distribution reads as which key, in which state, with which DS
// verdict (tdns-mp #102): the key tag and role instead of the public key,
// and the state its sender gave it beside each record.
func TestDescribeSyncShowsEachKeyWithItsState(t *testing.T) {
	ksk, kskTag := testDNSKEY(t, 257, testKSKPub)
	zsk, zskTag := testDNSKEY(t, 256, testZSKPub)
	msg := &AgentMsgPost{
		MessageType:    AgentMsgNotify,
		OriginatorID:   "agent.p1.example.",
		DeliveredBy:    "agent.p2.example.",
		Zone:           "example.com.",
		DistributionID: "d-1",
		Time:           time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		Operations: []core.RROperation{
			{
				Operation: "replace",
				RRtype:    "DNSKEY",
				Records:   []string{ksk, zsk},
				KeyStates: []core.KeyState{
					{KeyTag: kskTag, State: "published", DS: boolp(true)},
					{KeyTag: zskTag, State: "active", DS: boolp(false)},
					{KeyTag: 999, State: "retired"},
				},
			},
			{Operation: "add", RRtype: "NS", Records: []string{"example.com. 3600 IN NS ns1.p1.example."}},
			{Operation: "delete", RRtype: "A", Records: []string{"not a record"}},
		},
	}
	got := msg.Describe()
	wantLines(t, got,
		"SYNC from agent.p1.example., zone example.com.\n",
		"\n  delivered by: agent.p2.example.\n",
		"\n  distribution: d-1\n",
		"\n  sent: 2026-09-30T12:00:00Z\n",
		"\n  replace DNSKEY (2 records)\n",
		fmt.Sprintf("\n    example.com. 3600 DNSKEY 257 3 15 key %d (KSK): DS yes, published\n", kskTag),
		fmt.Sprintf("\n    example.com. 3600 DNSKEY 256 3 15 key %d (ZSK): DS no, active\n", zskTag),
		"\n    key 999 (no record in this operation): DS unset, retired\n",
		"\n  add NS (1 record)\n    example.com. 3600 NS ns1.p1.example.\n",
		"\n  delete A (1 record)\n    not a record (not parsed)",
	)
	if strings.Contains(got, testKSKPub) || strings.Contains(got, testZSKPub) {
		t.Errorf("the description carries a public key:\n%s", got)
	}
}

// A sender that predates key states sends none: the DNSKEY records then
// carry no state at all rather than "no state sent" on every key.
func TestDescribeDNSKEYWithoutKeyStates(t *testing.T) {
	ksk, kskTag := testDNSKEY(t, 257, testKSKPub)
	got := (&AgentMsgPost{
		MessageType:  AgentMsgNotify,
		OriginatorID: "agent.p1.example.",
		Zone:         "example.com.",
		Operations:   []core.RROperation{{Operation: "add", RRtype: "DNSKEY", Records: []string{ksk}}},
	}).Describe()
	line := fmt.Sprintf("key %d (KSK)", kskTag)
	wantLines(t, got, line)
	if strings.Contains(got, line+":") {
		t.Errorf("a DNSKEY sent without key states is shown with one:\n%s", got)
	}
}

func TestDescribeRfiAndLegacyRecordsAndPublish(t *testing.T) {
	got := (&AgentMsgPost{
		MessageType:  AgentMsgRfi,
		OriginatorID: "agent.p1.example.",
		Zone:         "example.com.",
		RfiType:      "ELECT-CALL",
		RfiSubtype:   "parent",
	}).Describe()
	wantLines(t, got, "RFI from agent.p1.example., zone example.com.", "\n  rfi: ELECT-CALL/parent")
	if strings.Contains(got, "no records") {
		t.Errorf("an RFI is described as carrying no records:\n%s", got)
	}

	got = (&AgentMsgPost{
		MessageType:  core.AgentMsgUpdate,
		OriginatorID: "agent.p1.example.",
		Zone:         "example.com.",
		Records:      map[string][]string{"example.com.": {"example.com. 3600 IN NS ns1.p1.example."}},
		Publish:      &core.PublishInstruction{KEYRRs: []string{"example.com. 3600 IN KEY 256 3 15 " + testZSKPub}, Locations: []string{"at-apex"}},
	}).Describe()
	wantLines(t, got,
		"UPDATE from agent.p1.example.",
		"\n  records in the legacy form (1 owner):\n    example.com. 3600 NS ns1.p1.example.",
		"\n  publish at at-apex: 1 KEY, no CDS\n    example.com. 3600 KEY 256 3 15 key ",
	)

	got = (&AgentMsgPost{MessageType: AgentMsgNotify, OriginatorID: "agent.p1.example."}).Describe()
	wantLines(t, got, "\n  no records")
}

func TestDescribeConfirmation(t *testing.T) {
	got := (&ConfirmationDetail{
		DistributionID: "d-2",
		Zone:           "example.com.",
		Source:         "combiner.p1.example.",
		Status:         "partial",
		Message:        "one rejected",
		AppliedRecords: []string{"example.com. 3600 IN NS ns1.p1.example."},
		RemovedRecords: []string{"example.com. 3600 IN NS ns0.p1.example."},
		RejectedItems:  []RejectedItemInfo{{Record: "example.com. 3600 IN A 192.0.2.1", Reason: "not allowed"}},
		IgnoredRecords: []string{"example.com. 3600 IN TXT \"x\""},
		Truncated:      true,
	}).Describe()
	wantLines(t, got,
		"CONFIRM partial from combiner.p1.example., zone example.com.\n",
		"\n  distribution: d-2\n",
		"\n  message: one rejected\n",
		"\n  applied (1):\n    example.com. 3600 NS ns1.p1.example.\n",
		"\n  removed (1):\n    example.com. 3600 NS ns0.p1.example.\n",
		"\n  rejected (1):\n    example.com. 3600 A 192.0.2.1: not allowed\n",
		"\n  ignored (1):\n    example.com. 3600 TXT \"x\"\n",
		"\n  truncated: the lists above are incomplete",
	)
}

func TestDescribeReports(t *testing.T) {
	got := (&AgentMsgReport{MessageType: AgentMsgHello, Identity: "agent.p1.example.", Zone: "example.com.", Transport: "dns", DistributionID: "h-1"}).Describe()
	wantLines(t, got, "HELLO from agent.p1.example., zone example.com.\n", "\n  transport: dns\n", "\n  distribution: h-1")
	got = (&AgentMsgReport{MessageType: AgentMsgBeat, Identity: "agent.p1.example.", BeatInterval: 30}).Describe()
	wantLines(t, got, "BEAT from agent.p1.example.\n", "\n  beat interval: 30s")
}

// Every other message type on the queues has its form too; each names its
// sender and zone and shows what it carried.
func TestDescribeTheOtherMessageTypes(t *testing.T) {
	for _, c := range []struct {
		name string
		got  string
		want []string
	}{
		{"keystate inventory", (&KeystateInventoryMsg{SenderID: "signer.p1.example.", Zone: "example.com.", Owned: true,
			Inventory: []KeyInventoryItem{{KeyTag: 4711, Algorithm: dns.ED25519, Flags: 257, State: "active", Pub: true, Sign: true, DS: boolp(true)}}}).Describe(),
			[]string{"KEYSTATE inventory from signer.p1.example., zone example.com.", "own state machine", "key 4711 (KSK) alg ED25519: active, publish yes, sign yes, DS yes"}},
		{"keystate signal", (&KeystateSignalMsg{SenderID: "agent.p1.example.", Zone: "example.com.", KeyTag: 4711, Signal: "foreign",
			ForeignKeys: []core.ForeignKeyState{{Provider: "p2", KeyState: core.KeyState{KeyTag: 815, State: "published"}}}}).Describe(),
			[]string{`KEYSTATE signal "foreign" from agent.p1.example.`, "\n  key: 4711", "\n    provider p2: key 815: DS unset, published"}},
		{"edits", (&EditsResponseMsg{SenderID: "combiner.p1.example.", Zone: "example.com.",
			AgentRecords: map[string]map[string][]string{"agent.p1.example.": {"example.com.": {"example.com. 3600 IN NS ns1.p1.example."}}}}).Describe(),
			[]string{"EDITS from combiner.p1.example.", "\n  agent agent.p1.example. (1 record):\n    example.com. 3600 NS ns1.p1.example."}},
		{"config", (&ConfigResponseMsg{SenderID: "combiner.p1.example.", Zone: "example.com.", Subtype: "upstream", ConfigData: map[string]string{"b": "2", "a": "1"}}).Describe(),
			[]string{"CONFIG upstream from combiner.p1.example.", "\n  a: 1\n  b: 2"}},
		{"audit", (&AuditResponseMsg{SenderID: "agent.p1.example.", Zone: "example.com.", AuditData: map[string]int{"rrs": 3}}).Describe(),
			[]string{"AUDIT from agent.p1.example.", `"rrs": 3`}},
		{"status update", (&StatusUpdateMsg{SenderID: "agent.p1.example.", Zone: "example.com.", SubType: "ds-sync", Result: "ok",
			DSRecords: []string{"example.com. 3600 IN DS 4711 15 2 " + strings.Repeat("ab", 32)}}).Describe(),
			[]string{"STATUS-UPDATE ds-sync from agent.p1.example.", "\n  result: ok", "\n  DS (1):\n    example.com. 3600 DS 4711 15 2 "}},
	} {
		t.Run(c.name, func(t *testing.T) { wantLines(t, c.got, c.want...) })
	}

	var none *AgentMsgPost
	if none.Describe() != "" {
		t.Error("a nil message has a description")
	}
}

// With what the sender said last time, each DNSKEY shows what changed: the
// news in a resent DNSKEY set is the key whose state moved.
func TestDescribeSinceShowsWhatChanged(t *testing.T) {
	ksk, kskTag := testDNSKEY(t, 257, testKSKPub)
	zsk, zskTag := testDNSKEY(t, 256, testZSKPub)
	msg := &AgentMsgPost{
		MessageType:  AgentMsgNotify,
		OriginatorID: "agent.p1.example.",
		Zone:         "example.com.",
		Operations: []core.RROperation{{
			Operation: "replace", RRtype: "DNSKEY", Records: []string{ksk, zsk},
			KeyStates: []core.KeyState{
				{KeyTag: kskTag, State: "active", DS: boolp(true)},
				{KeyTag: zskTag, State: "standby", DS: boolp(false)},
			},
		}},
	}
	got := msg.DescribeSince(map[uint16]core.KeyState{
		zskTag: {KeyTag: zskTag, State: "published", DS: boolp(false)},
		999:    {KeyTag: 999, State: "retired", DS: boolp(true)},
	})
	wantLines(t, got,
		fmt.Sprintf("key %d (ZSK): DS no, standby (was: published)\n", zskTag),
		fmt.Sprintf("key %d (KSK): DS yes, active (new)\n", kskTag),
		"\n    key 999: no longer sent (was: DS yes, retired)",
	)

	got = msg.DescribeSince(map[uint16]core.KeyState{
		kskTag: {KeyTag: kskTag, State: "active", DS: boolp(false)},
		zskTag: {KeyTag: zskTag, State: "standby", DS: boolp(false)},
	})
	wantLines(t, got,
		fmt.Sprintf("key %d (KSK): DS yes (was: no), active\n", kskTag),
		fmt.Sprintf("key %d (ZSK): DS no, standby", zskTag),
	)
	if strings.Contains(got, "standby (was") || strings.Contains(got, "(new)") || strings.Contains(got, "no longer sent") {
		t.Errorf("an unchanged key is shown as changed:\n%s", got)
	}

	if msg.DescribeSince(nil) != msg.Describe() {
		t.Error("DescribeSince(nil) is not Describe")
	}
}

// The summary is the message's operations in one line: what a list of
// messages shows beside the type, the sender and the counts.
func TestSummaryIsTheOperationHeadings(t *testing.T) {
	ksk, _ := testDNSKEY(t, 257, testKSKPub)
	for _, c := range []struct {
		msg  *AgentMsgPost
		want string
	}{
		{&AgentMsgPost{Operations: []core.RROperation{{Operation: "replace", RRtype: "DNSKEY", Records: []string{ksk, ksk, ksk}}}}, "replace DNSKEY (3 records)"},
		{&AgentMsgPost{Operations: []core.RROperation{
			{Operation: "replace", RRtype: "DNSKEY", Records: []string{ksk}},
			{Operation: "delete", RRtype: "NS"},
		}}, "replace DNSKEY (1 record); delete NS (no records)"},
		{&AgentMsgPost{Records: map[string][]string{"example.com.": {"example.com. 3600 IN NS ns1.example.", "example.com. 3600 IN NS ns2.example."}}}, "2 records in the legacy form"},
		{&AgentMsgPost{}, "no records"},
	} {
		if got := c.msg.Summary(); got != c.want {
			t.Errorf("Summary() = %q, want %q", got, c.want)
		}
	}
}
