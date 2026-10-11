/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func dnskeySyncFrom(t *testing.T, zone, sender string) *AgentMsgPostPlus {
	t.Helper()
	ksk, _ := testDNSKEY(t, 257, testKSKPub)
	return &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{
		MessageType:  AgentMsgNotify,
		OriginatorID: AgentId(sender),
		Zone:         ZoneName(zone),
		Operations:   []core.RROperation{{Operation: "add", RRtype: "DNSKEY", Records: []string{ksk}}},
	}}
}

// auditRolesZone is trackTestZone (signers us and p2, p3 a member that
// does not sign) made Ready: the auditor judges only a zone it serves.
func auditRolesZone(t *testing.T, name string) string {
	t.Helper()
	mpzd := trackTestZone(t, name)
	mpzd.Ready = true
	return mpzd.ZoneName
}

func nonSignerObservations(zs *AuditZoneState) []string {
	var out []string
	for _, o := range zs.SnapshotObservations() {
		if strings.Contains(o.Message, "non-signer") {
			out = append(out, o.Provider)
		}
	}
	return out
}

// A DNSKEY sync that arrives before its sender's first beat for the zone is
// judged by the sender's role in the zone, not by the absence of a beat
// (#108): a signer's is not flagged, a member that does not sign is, and
// the role is recorded on the provider as a beat would record it.
func TestADNSKEYSyncBeforeTheFirstBeatIsJudgedByTheZone(t *testing.T) {
	zone := auditRolesZone(t, "roles.audit.example.") // signers us, p2; p3 serves only
	e := &AuditorEngine{stateManager: NewAuditStateManager()}

	e.recordSyncMsg(dnskeySyncFrom(t, zone, "agent.p2.example."))
	zs := e.stateManager.GetZone(zone)
	if zs == nil {
		t.Fatal("the sync created no zone state")
	}
	if got := nonSignerObservations(zs); len(got) != 0 {
		t.Errorf("a signer's DNSKEY sync before its first beat was flagged: %v", got)
	}
	zs.mu.RLock()
	ps := zs.Providers["agent.p2.example."]
	zs.mu.RUnlock()
	if ps == nil || !ps.IsSigner || ps.Label != "p2" {
		t.Errorf("provider after its first sync = %+v, want label p2, a signer", ps)
	}

	e.recordSyncMsg(dnskeySyncFrom(t, zone, "agent.p3.example."))
	if got := nonSignerObservations(zs); len(got) != 1 || got[0] != "agent.p3.example." {
		t.Errorf("non-signer observations = %v, want the one for p3, which does not sign", got)
	}

	// A beat without a label (the zone not resolved at that moment) keeps
	// the label the sync recorded.
	zs.UpdateProviderBeat("agent.p2.example.", "", "OPERATIONAL", true)
	zs.mu.RLock()
	label := zs.Providers["agent.p2.example."].Label
	zs.mu.RUnlock()
	if label != "p2" {
		t.Errorf("label after a beat without one = %q, want p2 kept", label)
	}
}

// While the zone's roles are not known at the auditor, there is nothing to
// judge a DNSKEY sync by, and no observation: the zone not loaded here, or
// the sender not an HSYNC3 member of it.
func TestADNSKEYSyncIsNotJudgedWithoutTheZonesRoles(t *testing.T) {
	loaded := auditRolesZone(t, "members.audit.example.")
	e := &AuditorEngine{stateManager: NewAuditStateManager()}

	e.recordSyncMsg(dnskeySyncFrom(t, "absent.audit.example.", "agent.p2.example."))
	e.recordSyncMsg(dnskeySyncFrom(t, loaded, "agent.nobody.example."))

	for _, zone := range []string{"absent.audit.example.", loaded} {
		if zs := e.stateManager.GetZone(zone); zs != nil {
			if got := nonSignerObservations(zs); len(got) != 0 {
				t.Errorf("zone %s: a DNSKEY sync was judged without the zone's roles: %v", zone, got)
			}
		}
	}
}

// twoLabelZone is a Ready zone where one agent holds two labels: p3, a
// server that does not sign, and p4, a signer. p1 signs on its own.
func twoLabelZone(t *testing.T, name string) string {
	t.Helper()
	mpzd := signerTestZone(t, name, newMPTestKeyDB(t))
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		t.Fatalf("apex: %v", err)
	}
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: mpzd.ZoneName, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 3600}
	}
	hp := &core.HSYNCPARAM{Value: []core.HSYNCPARAMKeyValue{
		&core.HSYNCPARAMServers{Servers: []string{"p1", "p3", "p4"}},
		&core.HSYNCPARAMSigners{Signers: []string{"p1", "p4"}},
	}}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNCPARAM), Data: hp}}})
	var h3s []dns.RR
	for _, m := range [][2]string{{"p1", "agent.p1.example."}, {"p3", "agent.p3.example."}, {"p4", "agent.p3.example."}} {
		h3s = append(h3s, &dns.PrivateRR{Hdr: hdr(core.TypeHSYNC3), Data: &core.HSYNC3{State: 1, Label: m[0], Identity: m[1], Upstream: "."}})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: h3s})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.InstallInitialSnapshot()
	mpzd.Ready = true
	return mpzd.ZoneName
}

// An agent that holds a signer label and a label that only serves signs the
// zone, whichever of its labels a lookup meets first; the label recorded is
// the same every time (the external review's C1 on #111).
func TestAnAgentWithASignerLabelAmongItsLabelsSigns(t *testing.T) {
	zone := twoLabelZone(t, "twolabel.audit.example.")
	for i := 0; i < 50; i++ {
		label, isSigner, known := zoneMemberRole(ZoneName(zone), "agent.p3.example.")
		if label != "p3" || !isSigner || !known {
			t.Fatalf("lookup %d: role = %q signer=%v known=%v; want p3, a signer, known", i, label, isSigner, known)
		}
	}

	e := &AuditorEngine{stateManager: NewAuditStateManager()}
	e.recordSyncMsg(dnskeySyncFrom(t, zone, "agent.p3.example."))
	zs := e.stateManager.GetZone(zone)
	if got := nonSignerObservations(zs); len(got) != 0 {
		t.Errorf("a DNSKEY sync from an agent holding a signer label was flagged: %v", got)
	}
	zs.mu.RLock()
	ps := zs.Providers["agent.p3.example."]
	zs.mu.RUnlock()
	if ps == nil || !ps.IsSigner || ps.Label != "p3" {
		t.Errorf("provider = %+v, want label p3, a signer", ps)
	}
}
