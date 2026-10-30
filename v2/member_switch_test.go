/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The switch (plan S15): every HSYNC3 provider is a member. An ON record is
 * a member with a role or without; a provider whose removal is under way is
 * one under the removal's stored identity, whatever its record says.
 */
package tdnsmp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

const (
	s15Delta = "agent.delta.example." // an ON record with no role
	s15Eps   = "agent.eps.example."   // an OFF record
	s15Zeta  = "agent.zeta.example."  // no record at all
)

// s15Records are a zone's instructions: alpha a server and a signer, beta a
// server, gamma an auditor, delta ON with no role and alpha its upstream,
// and eps OFF.
func s15Records(serial int, records ...string) []string {
	out := []string{
		`3600 IN HSYNC3 ON alpha ` + acAlpha + ` .`,
		`3600 IN HSYNC3 ON beta ` + acBeta + ` alpha`,
		`3600 IN HSYNC3 ON gamma ` + acGamma + ` .`,
		`3600 IN HSYNC3 ON delta ` + s15Delta + ` alpha`,
		`3600 IN HSYNC3 OFF eps ` + s15Eps + ` .`,
	}
	out = append(out, records...)
	return append(out, `3600 IN HSYNCPARAM `+numberedText(fmt.Sprintf(`serial="%d" servers="alpha,beta" signers="alpha" auditors="gamma"`, serial)))
}

// s15Bridge is alpha's transport with a registry, as GetZoneAgentData and
// admission read them.
func s15Bridge() *MPTransportBridge {
	ar := &AgentRegistry{S: core.NewStringer[AgentId, *Agent](), LocalAgent: &MultiProviderConf{Identity: acAlpha}}
	return &MPTransportBridge{TransportManager: &transport.TransportManager{LocalID: acAlpha}, agentRegistry: ar, getZone: tdns.Zones.Get}
}

// keepRemoval keeps a removal under way in the zone at the store, as the
// leader's first step of a removal names it (S12, S17b).
func keepRemoval(t *testing.T, s *InstructionStore, zone, label, identity string) {
	t.Helper()
	if err := s.update(zone, func(z *zoneSerials) error {
		z.Removals = append(z.Removals, Removal{Label: label, Identity: identity, Since: time.Now()})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The three sets of a reading: every ON record is a member, with a role or
// without; servers= and signers= vote; auditors= alone audits. An OFF
// record is no member. HSYNC3 with no HSYNCPARAM has no reading (#308), and
// no members.
func TestMembersVotingMembersAndAuditorsOfAZone(t *testing.T) {
	in := readOf(t, s15Records(7)...)
	members, voting, auditors := participantsOf(in)
	if want := []string{acAlpha, acBeta, s15Delta, acGamma}; !slices.Equal(members, want) {
		t.Errorf("members %v, want %v", members, want)
	}
	if want := []string{acAlpha, acBeta}; !slices.Equal(voting, want) {
		t.Errorf("voting members %v, want %v", voting, want)
	}
	if want := []string{acGamma}; !slices.Equal(auditors, want) {
		t.Errorf("auditors %v, want %v", auditors, want)
	}
	for id, want := range map[string]string{
		acAlpha: "signer,server", acBeta: "server", acGamma: standingNameAuditor,
		s15Delta: standingNameNoRole, s15Eps: standingNameNotListed, s15Zeta: standingNameNotListed,
	} {
		if got := standingName(in, members, voting, auditors, id); got != want {
			t.Errorf("%s: standing %q, want %q", id, got, want)
		}
	}
	if _, err := ReadInstructions(apexOf(t, `3600 IN HSYNC3 ON alpha `+acAlpha+` .`)); !errors.Is(err, errNoHsyncparam) {
		t.Errorf("HSYNC3 with no HSYNCPARAM: %v, want %v", err, errNoHsyncparam)
	}
	if m, v, a := participantsOf(nil); m != nil || v != nil || a != nil {
		t.Errorf("no reading: %v %v %v", m, v, a)
	}
}

// A member with no role is no auditor: AuditorsForZone, whose distributions'
// final confirmations the auditor is copied, names the auditor alone.
func TestAMemberWithNoRoleIsNoAuditor(t *testing.T) {
	mpzd := instrTestZone(t, "noauditor.s15.example.", s15Records(7)...)
	zone := ZoneName(mpzd.ZoneName)
	if got := AuditorsForZone(zone); !slices.Equal(got, []AgentId{acGamma}) {
		t.Errorf("the auditors %v, want gamma alone", got)
	}
	if got := ParticipantsForZone(zone); !slices.Contains(got, AgentId(s15Delta)) || slices.Contains(got, AgentId(s15Eps)) {
		t.Errorf("the members %v: want delta, with no role, and not eps, OFF", got)
	}
}

// Membership is read from the active instructions, not from the copy: a
// record the copy has and the active serial has not is no member, and one
// the active serial has with no role is.
func TestMembershipIsReadFromTheActiveInstructions(t *testing.T) {
	withStore(t, nil)
	mpzd := instrTestZone(t, "active.s15.example.", s15Records(7)...)
	zone := ZoneName(mpzd.ZoneName)
	if !slices.Contains(ParticipantsForZone(zone), AgentId(s15Delta)) {
		t.Fatal("delta, ON with no role in the copy, is no member with no store")
	}
	s := newStore(t)
	withStore(t, s)
	activeAs(t, s, mpzd.ZoneName, readOf(t,
		`3600 IN HSYNC3 ON alpha `+acAlpha+` .`,
		`3600 IN HSYNC3 ON beta `+acBeta+` .`,
		`3600 IN HSYNC3 ON zeta `+s15Zeta+` .`,
		`3600 IN HSYNCPARAM `+numberedText(`serial="8" servers="alpha,beta"`)))
	got := ParticipantsForZone(zone)
	if slices.Contains(got, AgentId(s15Delta)) {
		t.Errorf("delta, with no record by the active serial, is a member by the copy: %v", got)
	}
	if !slices.Contains(got, AgentId(s15Zeta)) {
		t.Errorf("zeta, ON with no role by the active serial, is no member: %v", got)
	}
	if m := zoneMakeUp(mpzd.ZoneName, instructionsFor(zone)); !slices.Equal(m.noRole, []string{s15Zeta}) {
		t.Errorf("the make-up's members with no role %v, want zeta", m.noRole)
	}
}

// A provider whose removal is under way stays a member, with no role, until
// its removal is done (design 3.3), whatever its record says: OFF, or no
// record at all.
func TestAProviderWhoseRemovalIsUnderWayStaysAMemberWhateverItsRecordSays(t *testing.T) {
	mpzd := instrTestZone(t, "removal.s15.example.", s15Records(7)...)
	zone := ZoneName(mpzd.ZoneName)
	s := newStore(t)
	withStore(t, s)
	activeAs(t, s, mpzd.ZoneName, readOf(t, s15Records(8)...))
	for _, id := range []string{s15Eps, s15Zeta} {
		if slices.Contains(ParticipantsForZone(zone), AgentId(id)) {
			t.Fatalf("%s is a member with no removal under way", id)
		}
	}
	keepRemoval(t, s, mpzd.ZoneName, "eps", s15Eps)   // its record OFF
	keepRemoval(t, s, mpzd.ZoneName, "zeta", s15Zeta) // no record
	for _, id := range []string{s15Eps, s15Zeta} {
		if !slices.Contains(ParticipantsForZone(zone), AgentId(id)) {
			t.Errorf("%s, whose removal is under way, is no member", id)
		}
		if got := zoneStandingName(mpzd.ZoneName, id); got != standingNameNoRole {
			t.Errorf("%s: standing %q, want %q", id, got, standingNameNoRole)
		}
		if isVotingMember(zone, id) || slices.Contains(AuditorsForZone(zone), AgentId(id)) {
			t.Errorf("%s, whose removal is under way, has a role", id)
		}
		if !noRoleMember(zone, AgentId(id)) {
			t.Errorf("%s is not waited for as a member with no role", id)
		}
	}
	if m := zoneMakeUp(mpzd.ZoneName, instructionsFor(zone)); !slices.Equal(m.noRole, []string{s15Delta, s15Eps, s15Zeta}) {
		t.Errorf("the make-up's members with no role %v", m.noRole)
	}
	zad, err := s15Bridge().agentRegistry.GetZoneAgentData(zone)
	if err != nil {
		t.Fatal(err)
	}
	if zad.Standing[AgentId(s15Zeta)] != standingNameNoRole {
		t.Errorf("the zone's agents' standings %v: zeta is no member with no role", zad.Standing)
	}
}

// A provider whose removal is under way is admitted under the removal's
// stored identity, its record gone.
func TestAProviderWhoseRemovalIsUnderWayIsAdmittedUnderItsStoredIdentity(t *testing.T) {
	mpzd := instrTestZone(t, "admitted.removal.s15.example.", s15Records(7)...)
	s := newStore(t)
	withStore(t, s)
	activeAs(t, s, mpzd.ZoneName, readOf(t, s15Records(8)...))
	tm := s15Bridge()
	if ok, _ := tm.isInHSYNC(s15Zeta, mpzd.ZoneName); ok {
		t.Fatal("zeta, with no record and no removal, is admitted")
	}
	keepRemoval(t, s, mpzd.ZoneName, "zeta", s15Zeta)
	if ok, why := tm.isInHSYNC(s15Zeta, mpzd.ZoneName); !ok {
		t.Errorf("zeta, whose removal is under way, is refused: %s", why)
	}
	tm.getZoneNames = func() []string { return []string{mpzd.ZoneName} }
	if ok, zone := tm.isInHSYNCAnyZone("Agent.ZETA.example"); !ok || zone != mpzd.ZoneName {
		t.Errorf("zeta in another case, by any zone: %v %q", ok, zone)
	}
}

// Zones of the same voting members, one with a member with no role and one
// without, are two groups: the member with no role is in the second's
// members, not among its voting members.
func TestAZoneWithAMemberWithNoRoleIsInAGroupOfItsOwn(t *testing.T) {
	withStore(t, nil)
	plain := instrTestZone(t, "plain.group.s15.example.",
		`3600 IN HSYNC3 ON alpha `+acAlpha+` .`, `3600 IN HSYNC3 ON beta `+acBeta+` .`,
		`3600 IN HSYNCPARAM `+numberedText(`serial="7" servers="alpha,beta"`))
	norole := instrTestZone(t, "norole.group.s15.example.",
		`3600 IN HSYNC3 ON alpha `+acAlpha+` .`, `3600 IN HSYNC3 ON beta `+acBeta+` .`, `3600 IN HSYNC3 ON delta `+s15Delta+` .`,
		`3600 IN HSYNCPARAM `+numberedText(`serial="7" servers="alpha,beta"`))
	pgm := NewProviderGroupManager(acAlpha)
	pgm.RecomputeGroups()
	a, b := pgm.GetGroupForZone(ZoneName(plain.ZoneName)), pgm.GetGroupForZone(ZoneName(norole.ZoneName))
	if a == nil || b == nil || a.GroupHash == b.GroupHash {
		t.Fatalf("the groups %+v and %+v, want two", a, b)
	}
	if !slices.Equal(b.VotingMembers, []string{acAlpha, acBeta}) || !slices.Equal(b.NoRole, []string{s15Delta}) ||
		!slices.Contains(b.Members, s15Delta) {
		t.Errorf("the group of the zone with a member with no role: %+v", b)
	}
	if b.GroupHash != ComputeGroupHash([]string{acAlpha, acBeta}, nil, []string{s15Delta}) {
		t.Errorf("the group's hash %s is not its make-up's", b.GroupHash)
	}
}

// zone mplist: the labels of the members with no role, and the agent's own
// standing in the This column.
func TestMplistShowsEachMembersStanding(t *testing.T) {
	withStore(t, nil)
	mpzd := instrTestZone(t, "mplist.s15.example.", s15Records(7)...)
	info := MPZoneInfoFromMPZoneData(mpzd)
	if !slices.Equal(info.NoRole, []string{"delta"}) {
		t.Errorf("NoRole %v, want [delta]", info.NoRole)
	}
	for id, want := range map[string]string{acAlpha: "signer,server", acBeta: "server", acGamma: "auditor",
		s15Delta: "member, no role", s15Eps: "not listed"} {
		if got := zoneStandingName(mpzd.ZoneName, id); got != want {
			t.Errorf("This for %s: %q, want %q", id, got, want)
		}
	}
}

// Every member is a recipient of the zone's distributions: the auditor,
// which confirms at once, and a member with no role, whose confirmation is
// waited for. An OFF record is none.
func TestADistributionWaitsForTheAuditor(t *testing.T) {
	withStore(t, nil)
	mpzd := instrTestZone(t, "recipients.s15.example.", s15Records(7)...)
	got := s15Bridge().GetDistributionRecipients(ZoneName(mpzd.ZoneName), true)
	slices.Sort(got)
	if want := []string{acBeta, s15Delta, acGamma}; !slices.Equal(got, want) {
		t.Errorf("the recipients %v, want %v", got, want)
	}
}

// A member with no role is waited for up to no-role-timeout, S12's time-out:
// with no voting member left to confirm, the wait for the CSYNC ends when
// it has run.
func TestAMemberWithNoRoleIsWaitedForWithTheTimeOut(t *testing.T) {
	withStore(t, nil)
	mpzd := instrTestZone(t, "timeout.s15.example.", s15Records(7)...)
	zone := ZoneName(mpzd.ZoneName)
	if !noRoleMember(zone, s15Delta) || noRoleMember(zone, acBeta) || noRoleMember(zone, acGamma) {
		t.Fatal("the members with no role: want delta alone")
	}
	now, timeout := time.Now(), 10*time.Minute
	if only, wait := noRoleOnly(zone, []string{s15Delta}, now.Add(-4*time.Minute), now, timeout); !only || wait != 6*time.Minute {
		t.Errorf("delta alone awaited: only %v, wait %s; want true and 6m0s", only, wait)
	}
	if only, _ := noRoleOnly(zone, []string{s15Delta, acBeta}, now, now, timeout); only {
		t.Error("a voting member awaited beside delta: the wait has a time-out")
	}
}

// A member with no role asks for no key: the zone's SIG(0) key is the
// voting members' (decision 46).
func TestAMemberThatDoesNotVoteAsksForNoKey(t *testing.T) {
	withStore(t, nil)
	mpzd := instrTestZone(t, "nokey.s15.example.", s15Records(7)...)
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: s15Delta})
	if conf.wantsZoneKey(context.Background(), ZoneName(mpzd.ZoneName)) {
		t.Error("a member with no role wants the zone's key")
	}
}

// The transfer set-up is answered to a member with no role, related to this
// agent by its record's upstream field: delta transfers the zone from
// alpha. A provider whose record is OFF is no member, and is refused.
func TestAMemberWithNoRoleIsAnsweredTheTransferSetUp(t *testing.T) {
	withStore(t, nil)
	mpzd := instrTestZone(t, "setup.s15.example.", s15Records(7)...)
	zone := ZoneName(mpzd.ZoneName)
	tm := s15Bridge()
	if why := tm.rfiSenderRefusal(zone, s15Delta, "CONFIG", "upstream"); why != "" {
		t.Errorf("the request for the transfer set-up from a member with no role is refused: %s", why)
	}
	if why := tm.rfiSenderRefusal(zone, s15Eps, "CONFIG", "upstream"); why == "" {
		t.Error("the request for the transfer set-up from an OFF record is answered")
	}
}

// A member with no role has loaded for the catch-up once its first load
// gave it its label, as a provider has: the zones PeerOperational asks
// about, and the own reader's re-reads, take it. The stub main_init puts
// in place, with no label, has not (the external review's F1).
func TestAZoneOfAMemberWithNoRoleIsLoadedForCatchUp(t *testing.T) {
	const zone = "loaded.norole.s15.example."
	catchUpZone(t, zone, []string{roleB}, nil, []string{roleA})
	mpzd, _ := Zones.Get(zone)
	set := func(d *MPdata) {
		mpzd.Lock()
		mpzd.MP.MPdata = d
		mpzd.Unlock()
	}
	set(&MPdata{Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}}) // main_init's stub
	if mpzd.loadedForCatchUp() {
		t.Error("the stub has loaded for the catch-up")
	}
	set(&MPdata{OurLabel: shortLabel(roleA)}) // a member with no role: no provider
	if !mpzd.loadedForCatchUp() {
		t.Fatal("a member with no role has not loaded for the catch-up")
	}
	r := newTrackerRig(t, roleA)
	if got := r.t.sharedZones(roleB); !slices.Contains(got, ZoneName(zone)) {
		t.Errorf("the zones asked about at b's beat: %v, want the zone", got)
	}
}

// A member with no role edits nothing, in an unsigned zone as in a signed
// one; the server does (the external review's F2).
func TestAMemberWithNoRoleMayNotEdit(t *testing.T) {
	withStore(t, nil)
	mpzd := instrTestZone(t, "noedits.s15.example.",
		`3600 IN HSYNC3 ON alpha `+acAlpha+` .`, `3600 IN HSYNC3 ON delta `+s15Delta+` .`,
		`3600 IN HSYNCPARAM `+numberedText(`serial="7" servers="alpha"`))
	mpzd.populateMPdata(&MultiProviderConf{Role: "agent", Identity: s15Delta}, signingSet{})
	if mpzd.MP.MPdata == nil || mpzd.MP.MPdata.OurLabel != "delta" {
		t.Fatalf("the member with no role's provider data: %+v", mpzd.MP.MPdata)
	}
	if !mpzd.MPOptions[OptMPDisallowEdits] || mpzd.MPOptions[tdns.OptAllowEdits] {
		t.Errorf("a member with no role in an unsigned zone: disallow %v, allow %v", mpzd.MPOptions[OptMPDisallowEdits], mpzd.MPOptions[tdns.OptAllowEdits])
	}
	mpzd.populateMPdata(&MultiProviderConf{Role: "agent", Identity: acAlpha}, signingSet{})
	if mpzd.MPOptions[OptMPDisallowEdits] || !mpzd.MPOptions[tdns.OptAllowEdits] {
		t.Errorf("the server in an unsigned zone: disallow %v, allow %v", mpzd.MPOptions[OptMPDisallowEdits], mpzd.MPOptions[tdns.OptAllowEdits])
	}
}
