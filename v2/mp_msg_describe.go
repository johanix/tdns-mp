/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The printable form of every message the peers exchange: one Describe
 * method per message type, each rendering what the message carried as
 * text, one item per line. Wherever a message is shown in full (the
 * auditor's event log details, the CLI) it is shown in this form, so a
 * sync reads the same in every place it appears.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// msgText collects a message's description: a heading, then one item per
// line, indented two spaces per level below it.
type msgText []string

func (t *msgText) add(depth int, format string, a ...any) {
	*t = append(*t, strings.Repeat("  ", depth)+fmt.Sprintf(format, a...))
}

func (t msgText) String() string { return strings.Join(t, "\n") }

// msgHeading is the first line of every description: the message type, who
// sent it and the zone it is about.
func msgHeading(kind, from, zone string) string {
	h := kind
	if from != "" {
		h += " from " + from
	}
	if zone != "" {
		h += ", zone " + zone
	}
	return h
}

func msgTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// dsWord renders the DS verdict a provider gives a key: a nil DS is a key
// the provider said nothing about, which is not the same as "no".
func dsWord(ds *bool) string {
	if ds == nil {
		return "unset"
	}
	return yesNo(*ds)
}

func countWord(n int, one, many string) string {
	switch n {
	case 0:
		return "no " + many
	case 1:
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func describeKeyState(ks core.KeyState) string {
	state := ks.State
	if state == "" {
		state = "no state"
	}
	return fmt.Sprintf("%s, DS %s", state, dsWord(ks.DS))
}

// describeRecord renders one RR string as "owner ttl TYPE rdata". A DNSKEY,
// CDNSKEY or KEY is named by its flags, protocol, algorithm and key tag
// rather than its public key. For a DNSKEY, states is what the sender said
// about its keys: the record then ends with that key's state and DS verdict.
// states is nil when the operation carried no key states at all.
func describeRecord(rrstr string, states map[uint16]core.KeyState) string {
	rr, err := dns.NewRR(rrstr)
	if err != nil || rr == nil {
		return rrstr + " (not parsed)"
	}
	h := rr.Header()
	typ := dns.Type(h.Rrtype).String()
	var key *dns.DNSKEY
	switch k := rr.(type) {
	case *dns.DNSKEY:
		key = k
	case *dns.CDNSKEY:
		key = &k.DNSKEY
	case *dns.KEY:
		key = &k.DNSKEY
	}
	if key == nil {
		rdata := strings.TrimSpace(strings.TrimPrefix(rr.String(), h.String()))
		return fmt.Sprintf("%s %d %s %s", h.Name, h.Ttl, typ, rdata)
	}
	tag := key.KeyTag()
	s := fmt.Sprintf("%s %d %s %d %d %d key %d", h.Name, h.Ttl, typ, key.Flags, key.Protocol, key.Algorithm, tag)
	if h.Rrtype != dns.TypeKEY {
		role := "ZSK"
		if key.Flags&dns.SEP != 0 {
			role = "KSK"
		}
		if key.Flags&dns.REVOKE != 0 {
			role += ", revoked"
		}
		s += " (" + role + ")"
	}
	if states != nil && h.Rrtype == dns.TypeDNSKEY {
		if ks, ok := states[tag]; ok {
			s += ": " + describeKeyState(ks)
		} else {
			s += ": no state sent"
		}
	}
	return s
}

// describeRecords adds one line per RR string, at depth.
func (t *msgText) describeRecords(depth int, rrs []string) {
	for _, rr := range rrs {
		t.add(depth, "%s", describeRecord(rr, nil))
	}
}

// describeOperation adds an operation: its kind and RR type, then each of
// its records, a DNSKEY with the state its sender gave it. A key state for a
// key tag none of the records carries is listed after the records.
func (t *msgText) describeOperation(depth int, op core.RROperation) {
	t.add(depth, "%s %s (%s)", op.Operation, op.RRtype, countWord(len(op.Records), "record", "records"))
	var states map[uint16]core.KeyState
	if len(op.KeyStates) > 0 {
		states = make(map[uint16]core.KeyState, len(op.KeyStates))
		for _, ks := range op.KeyStates {
			states[ks.KeyTag] = ks
		}
	}
	seen := map[uint16]bool{}
	for _, rrstr := range op.Records {
		t.add(depth+1, "%s", describeRecord(rrstr, states))
		if rr, err := dns.NewRR(rrstr); err == nil {
			if k, ok := rr.(*dns.DNSKEY); ok {
				seen[k.KeyTag()] = true
			}
		}
	}
	for _, ks := range op.KeyStates {
		if !seen[ks.KeyTag] {
			t.add(depth+1, "key %d (no record in this operation): %s", ks.KeyTag, describeKeyState(ks))
		}
	}
}

// Describe renders a sync, update, rfi or status message: who sent it and
// who delivered it, its distribution, each operation with its records (a
// DNSKEY with the key state and DS verdict its sender gave it), records in
// the legacy per-owner form, and a publish instruction.
func (m *AgentMsgPost) Describe() string {
	if m == nil {
		return ""
	}
	var t msgText
	t.add(0, "%s", msgHeading(strings.ToUpper(string(m.MessageType)), string(m.OriginatorID), string(m.Zone)))
	if m.DeliveredBy != "" && m.DeliveredBy != m.OriginatorID {
		t.add(1, "delivered by: %s", m.DeliveredBy)
	}
	if m.YourIdentity != "" {
		t.add(1, "to: %s", m.YourIdentity)
	}
	if m.DistributionID != "" {
		t.add(1, "distribution: %s", m.DistributionID)
	}
	if !m.Time.IsZero() {
		t.add(1, "sent: %s", msgTime(m.Time))
	}
	if m.RfiType != "" {
		rfi := m.RfiType
		if m.RfiSubtype != "" {
			rfi += "/" + m.RfiSubtype
		}
		t.add(1, "rfi: %s", rfi)
	}
	if m.ZoneClass != "" {
		t.add(1, "zone class: %s", m.ZoneClass)
	}
	for _, op := range m.Operations {
		t.describeOperation(1, op)
	}
	if len(m.Records) > 0 {
		note := ""
		if len(m.Operations) > 0 {
			note = ", ignored: the operations take precedence"
		}
		t.add(1, "records in the legacy form (%s%s):", countWord(len(m.Records), "owner", "owners"), note)
		owners := make([]string, 0, len(m.Records))
		for owner := range m.Records {
			owners = append(owners, owner)
		}
		sort.Strings(owners)
		for _, owner := range owners {
			t.describeRecords(2, m.Records[owner])
		}
	}
	if p := m.Publish; p != nil {
		if len(p.Locations) == 0 {
			t.add(1, "publish: retract")
		} else {
			t.add(1, "publish at %s: %s, %s", strings.Join(p.Locations, ", "),
				countWord(len(p.KEYRRs), "KEY", "KEYs"), countWord(len(p.CDSRRs), "CDS", "CDS"))
		}
		t.describeRecords(2, p.KEYRRs)
		t.describeRecords(2, p.CDSRRs)
	}
	if len(m.Operations) == 0 && len(m.Records) == 0 && m.Publish == nil && m.MessageType != AgentMsgRfi {
		t.add(1, "no records")
	}
	return t.String()
}

// Describe renders a hello, beat or ping: who sent it, over which transport,
// and the beat interval of a beat.
func (r *AgentMsgReport) Describe() string {
	if r == nil {
		return ""
	}
	var t msgText
	t.add(0, "%s", msgHeading(strings.ToUpper(string(r.MessageType)), string(r.Identity), string(r.Zone)))
	if r.Transport != "" {
		t.add(1, "transport: %s", r.Transport)
	}
	if r.DistributionID != "" {
		t.add(1, "distribution: %s", r.DistributionID)
	}
	if r.BeatInterval > 0 {
		t.add(1, "beat interval: %s", time.Duration(r.BeatInterval)*time.Second)
	}
	if r.RfiType != "" {
		t.add(1, "rfi: %s", r.RfiType)
	}
	return t.String()
}

// Describe renders a confirmation: its status, and the records the
// confirming party applied, removed, rejected (each with the reason) and
// ignored.
func (c *ConfirmationDetail) Describe() string {
	if c == nil {
		return ""
	}
	var t msgText
	t.add(0, "%s", msgHeading("CONFIRM "+c.Status, c.Source, string(c.Zone)))
	if c.DistributionID != "" {
		t.add(1, "distribution: %s", c.DistributionID)
	}
	if !c.Timestamp.IsZero() {
		t.add(1, "sent: %s", msgTime(c.Timestamp))
	}
	if c.Message != "" {
		t.add(1, "message: %s", c.Message)
	}
	for _, l := range []struct {
		name string
		rrs  []string
	}{{"applied", c.AppliedRecords}, {"removed", c.RemovedRecords}} {
		if len(l.rrs) > 0 {
			t.add(1, "%s (%d):", l.name, len(l.rrs))
			t.describeRecords(2, l.rrs)
		}
	}
	if len(c.RejectedItems) > 0 {
		t.add(1, "rejected (%d):", len(c.RejectedItems))
		for _, ri := range c.RejectedItems {
			t.add(2, "%s: %s", describeRecord(ri.Record, nil), ri.Reason)
		}
	}
	if len(c.IgnoredRecords) > 0 {
		t.add(1, "ignored (%d):", len(c.IgnoredRecords))
		t.describeRecords(2, c.IgnoredRecords)
	}
	if c.Truncated {
		t.add(1, "truncated: the lists above are incomplete")
	}
	return t.String()
}

// Describe renders a signer's key inventory: each key with its state and
// the publish, sign and DS columns beside it.
func (m *KeystateInventoryMsg) Describe() string {
	if m == nil {
		return ""
	}
	var t msgText
	t.add(0, "%s", msgHeading("KEYSTATE inventory", m.SenderID, m.Zone))
	if m.Owned {
		t.add(1, "the zone's keys are run by the signer's own state machine")
	}
	if len(m.Inventory) == 0 {
		t.add(1, "no keys")
	}
	for _, k := range m.Inventory {
		role := "ZSK"
		if k.Flags&dns.SEP != 0 {
			role = "KSK"
		}
		t.add(1, "key %d (%s) alg %s: %s, publish %s, sign %s, DS %s", k.KeyTag, role,
			dns.AlgorithmToString[k.Algorithm], k.State, yesNo(k.Pub), yesNo(k.Sign), dsWord(k.DS))
	}
	return t.String()
}

// Describe renders a key state signal: the signal, the key it is about, and
// for a "foreign" signal the key states the other providers sent.
func (m *KeystateSignalMsg) Describe() string {
	if m == nil {
		return ""
	}
	var t msgText
	t.add(0, "%s", msgHeading(fmt.Sprintf("KEYSTATE signal %q", m.Signal), m.SenderID, m.Zone))
	if m.KeyTag != 0 {
		t.add(1, "key: %d", m.KeyTag)
	}
	if m.Message != "" {
		t.add(1, "message: %s", m.Message)
	}
	if !m.At.IsZero() {
		t.add(1, "answers the distribution sent at: %s", msgTime(m.At))
	}
	if len(m.ForeignKeys) > 0 {
		t.add(1, "foreign keys (%d):", len(m.ForeignKeys))
		for _, fk := range m.ForeignKeys {
			t.add(2, "provider %s: key %d: %s", fk.Provider, fk.KeyTag, describeKeyState(fk.KeyState))
		}
	}
	return t.String()
}

// Describe renders an edits response: the records each agent contributed.
func (m *EditsResponseMsg) Describe() string {
	if m == nil {
		return ""
	}
	var t msgText
	t.add(0, "%s", msgHeading("EDITS", m.SenderID, m.Zone))
	if len(m.AgentRecords) == 0 {
		t.add(1, "no records")
	}
	agents := make([]string, 0, len(m.AgentRecords))
	for a := range m.AgentRecords {
		agents = append(agents, a)
	}
	sort.Strings(agents)
	for _, a := range agents {
		owners := make([]string, 0, len(m.AgentRecords[a]))
		n := 0
		for owner, rrs := range m.AgentRecords[a] {
			owners = append(owners, owner)
			n += len(rrs)
		}
		sort.Strings(owners)
		t.add(1, "agent %s (%s):", a, countWord(n, "record", "records"))
		for _, owner := range owners {
			t.describeRecords(2, m.AgentRecords[a][owner])
		}
	}
	return t.String()
}

// Describe renders a config response: its subtype and each key and value.
func (m *ConfigResponseMsg) Describe() string {
	if m == nil {
		return ""
	}
	var t msgText
	t.add(0, "%s", msgHeading(strings.TrimSpace("CONFIG "+m.Subtype), m.SenderID, m.Zone))
	keys := make([]string, 0, len(m.ConfigData))
	for k := range m.ConfigData {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.add(1, "%s: %s", k, m.ConfigData[k])
	}
	return t.String()
}

// Describe renders an audit response. Its data has no fixed shape on the
// wire, so it is shown as the JSON it arrived as.
func (m *AuditResponseMsg) Describe() string {
	if m == nil {
		return ""
	}
	var t msgText
	t.add(0, "%s", msgHeading("AUDIT", m.SenderID, m.Zone))
	if m.AuditData == nil {
		t.add(1, "no audit data")
		return t.String()
	}
	buf, err := json.MarshalIndent(m.AuditData, "", "  ")
	if err != nil {
		t.add(1, "audit data (%T) could not be rendered: %v", m.AuditData, err)
		return t.String()
	}
	for _, l := range strings.Split(string(buf), "\n") {
		t.add(1, "%s", l)
	}
	return t.String()
}

// Describe renders a status update: its subtype, result, and the NS and DS
// records it reports.
func (m *StatusUpdateMsg) Describe() string {
	if m == nil {
		return ""
	}
	var t msgText
	t.add(0, "%s", msgHeading(strings.TrimSpace("STATUS-UPDATE "+m.SubType), m.SenderID, m.Zone))
	if m.Result != "" {
		t.add(1, "result: %s", m.Result)
	}
	if m.Msg != "" {
		t.add(1, "message: %s", m.Msg)
	}
	for _, l := range []struct {
		name string
		rrs  []string
	}{{"NS", m.NSRecords}, {"DS", m.DSRecords}} {
		if len(l.rrs) > 0 {
			t.add(1, "%s (%d):", l.name, len(l.rrs))
			t.describeRecords(2, l.rrs)
		}
	}
	return t.String()
}
