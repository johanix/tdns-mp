/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// gossipRolesZone is a Ready zone whose HSYNC3 labels are aud (the
// auditor), p1 and p2, and p3 and p4 held by one agent. Its identities do
// not sort as its labels do: the auditor's sorts last.
func gossipRolesZone(t *testing.T, name string) string {
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
		&core.HSYNCPARAMServers{Servers: []string{"p1", "p2", "p3", "p4"}},
		&core.HSYNCPARAMSigners{Signers: []string{"p1", "p2"}},
		&core.HSYNCPARAMAuditors{Auditors: []string{"aud"}},
	}}
	apex.RRtypes.Set(core.TypeHSYNCPARAM, core.RRset{RRs: []dns.RR{&dns.PrivateRR{Hdr: hdr(core.TypeHSYNCPARAM), Data: hp}}})
	var h3s []dns.RR
	for label, id := range map[string]string{
		"aud": "zz-auditor.example.", "p1": "agent.p1.example.", "p2": "agent.p2.example.",
		"p3": "agent.p3.example.", "p4": "agent.p3.example.",
	} {
		h3s = append(h3s, &dns.PrivateRR{Hdr: hdr(core.TypeHSYNC3), Data: &core.HSYNC3{State: 1, Label: label, Identity: id, Upstream: "."}})
	}
	apex.RRtypes.Set(core.TypeHSYNC3, core.RRset{RRs: h3s})
	mpzd.Data.Set(mpzd.ZoneName, *apex)
	mpzd.InstallInitialSnapshot()
	mpzd.Ready = true
	return mpzd.ZoneName
}

// The zone view's gossip matrix names each reporter by its role label in
// the zone and orders the reporters as the columns, so a reporter's own
// cell (no state for itself) is on the diagonal (#109). A reporter with no
// label in the zone keeps its identity and comes last.
func TestTheZoneGossipMatrixRowsAreTheColumnsLabels(t *testing.T) {
	zone := gossipRolesZone(t, "gossip.roles.example.")
	reporters := []string{"zz-auditor.example.", "agent.p1.example.", "agent.p2.example.", "agent.p3.example.", "agent.stranger.example."}
	gst := NewGossipStateTable("zz-auditor.example.")
	gst.States["g1"] = map[string]*MemberState{}
	for _, r := range reporters {
		peers := map[string]string{}
		for _, p := range reporters {
			if p != r {
				peers[p] = "OPERATIONAL"
			}
		}
		gst.States["g1"][r] = &MemberState{Identity: r, Timestamp: time.Now(), PeerStates: peers}
	}
	ar := &AgentRegistry{GossipStateTable: gst}
	dto := snapshotGossipMatrix(ar, &ProviderGroup{GroupHash: "g1", Members: reporters}, "g1", zone)
	if dto == nil {
		t.Fatal("no matrix")
	}

	var got []string
	for _, r := range dto.Rows {
		got = append(got, r.Reporter+"="+r.Label)
	}
	want := []string{"zz-auditor.example.=aud", "agent.p1.example.=p1", "agent.p2.example.=p2", "agent.p3.example.=p3, p4", "agent.stranger.example.="}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("rows = %v\nwant   %v (the columns are %v)", got, want, dto.ColumnLabels)
	}
	// The diagonal: in each labelled row, the reporter's own column(s).
	for _, r := range dto.Rows {
		for _, lbl := range strings.Split(r.Label, ", ") {
			if lbl == "" {
				continue
			}
			if s, ok := r.PeerStates[dto.LabelToIdentity[lbl]]; ok {
				t.Errorf("row %s has state %q in its own column %s", r.Label, s, lbl)
			}
		}
	}

	ws, err := newAuditorWebServer(&Config{}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ws.tmpl.ExecuteTemplate(&buf, "gossip-matrix-inner", &WebData{Zone: zone, Gossip: []GossipMatrixDTO{*dto}}); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range regexp.MustCompile(`<strong title="[^"]*">([^<]*)</strong>`).FindAllStringSubmatch(buf.String(), -1) {
		names = append(names, m[1])
	}
	if strings.Join(names, " ") != "aud p1 p2 p3, p4 stranger" {
		t.Errorf("row names on the page = %q, want the labels in column order, the unlabelled reporter last", names)
	}
}
