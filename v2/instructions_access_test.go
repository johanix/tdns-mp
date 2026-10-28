/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * One accessor; the hooks at activation and at a first load (plan S3).
 */
package tdnsmp

import (
	"bytes"
	"io"
	"log"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
)

const (
	acAlpha = "agent.alpha.example."
	acBeta  = "agent.beta.example."
	acGamma = "agent.gamma.example."
)

// acRecords are a zone's instructions in zone-file form: alpha and beta ON,
// gamma's record per gamma ("ON", "OFF" or "" for none), and HSYNCPARAM.
func acRecords(gamma, param string) []string {
	out := []string{
		`3600 IN HSYNC3 ON alpha ` + acAlpha + ` .`,
		`3600 IN HSYNC3 ON beta ` + acBeta + ` alpha`,
	}
	if gamma != "" {
		out = append(out, `3600 IN HSYNC3 `+gamma+` gamma `+acGamma+` .`)
	}
	if param != "" {
		out = append(out, `3600 IN HSYNCPARAM `+param)
	}
	return out
}

// withStore installs s as the daemon's store of serials for the test.
func withStore(t *testing.T, s *InstructionStore) {
	t.Helper()
	prev := instrStore.Load()
	instrStore.Store(s)
	t.Cleanup(func() { instrStore.Store(prev) })
}

// activeAs makes in the zone's active instructions in the store, as a thaw
// would; the copy stays what it is.
func activeAs(t *testing.T, s *InstructionStore, zone string, in *Instructions) {
	t.Helper()
	if err := s.update(zone, func(z *zoneSerials) error {
		z.Active = &heldSerial{SerialDigest: sd(in), Reading: in}
		z.Enforced = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// zoneCopy is a copy of the zone with these apex records, loaded and not
// registered: an incoming copy at a refresh.
func zoneCopy(t *testing.T, name string, records ...string) *tdns.ZoneData {
	t.Helper()
	text := name + " 3600 IN SOA ns1." + name + " hostmaster." + name + " 2 7200 1800 604800 7200\n" +
		name + " 3600 IN NS ns1." + name + "\nns1." + name + " 3600 IN A 192.0.2.1\n"
	for _, r := range records {
		text += name + " " + r + "\n"
	}
	zd := &tdns.ZoneData{
		ZoneName:  name,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Primary,
		Logger:    log.New(io.Discard, "", 0),
		Options:   map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
	}
	if _, _, err := zd.ReadZoneData(text, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	return zd
}

// captureZonesLog collects what the zones logger says during the test.
func captureZonesLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	saved := lg
	lg = slog.New(slog.NewJSONHandler(&buf, nil))
	t.Cleanup(func() { lg = saved })
	return &buf
}

func changedBetween(t *testing.T, name string, before, after []string) bool {
	t.Helper()
	old := instrTestZone(t, name, before...)
	changed, _, err := HsyncChanged(old.ZoneData, zoneCopy(t, name, after...))
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func TestAReorderedListIsNoChange(t *testing.T) {
	if changedBetween(t, "reorder.access.example.",
		acRecords("", `serial="7" servers="alpha,beta" signers="alpha"`),
		acRecords("", `serial="7" servers="beta,alpha" signers="alpha"`)) {
		t.Error("servers= in another order is a change")
	}
}

func TestAnOffRecordsFieldsAreNoChange(t *testing.T) {
	param := `serial="7" servers="alpha,beta" signers="alpha"`
	if changedBetween(t, "offfields.access.example.",
		acRecords("OFF", param),
		append(acRecords("", param), `3600 IN HSYNC3 OFF gamma agent.other.example. beta`)) {
		t.Error("an OFF record's identity and upstream are a change")
	}
}

func TestATTLOrSignatureChangeIsNoChange(t *testing.T) {
	param := `serial="7" servers="alpha,beta" signers="alpha"`
	var shorter []string
	for _, r := range acRecords("ON", param) {
		shorter = append(shorter, strings.Replace(r, "3600", "300", 1))
	}
	if changedBetween(t, "ttl.access.example.", acRecords("ON", param), shorter) {
		t.Error("another TTL is a change")
	}
}

func TestARoleMoveIsAChange(t *testing.T) {
	if !changedBetween(t, "rolemove.access.example.",
		acRecords("", `serial="7" servers="alpha,beta" signers="alpha"`),
		acRecords("", `serial="7" servers="alpha" signers="alpha,beta"`)) {
		t.Error("a role moved from servers= to signers= is no change")
	}
	if !changedBetween(t, "raised.access.example.",
		acRecords("", `serial="7" servers="alpha,beta"`),
		acRecords("", `serial="8" servers="alpha,beta"`)) {
		t.Error("a raised serial with the same contents is no change")
	}
}

// postRefresh runs the zone's post-refresh as an agent, with the analysis a
// pre-refresh left: the active instructions before the refresh.
func postRefresh(t *testing.T, mpzd *MPZoneData, before *Instructions, first bool) {
	t.Helper()
	mpzd.EnsureMP()
	mpzd.MP.RefreshAnalysis = &ZoneRefreshAnalysis{ActiveBefore: before, FirstLoad: first}
	mpzd.PostRefresh(nil, nil)
}

func TestTheHookGetsTheTwoActiveReadings(t *testing.T) {
	asMPAgent(t)
	logs := captureZonesLog(t)
	mpzd := instrTestZone(t, "hook.access.example.", acRecords("", `serial="8" servers="alpha,beta"`)...)
	before := readOf(t, acRecords("", `serial="7" servers="alpha"`)...)
	postRefresh(t, mpzd, before, false)
	if !strings.Contains(logs.String(), `"from":"7 (`+before.Digest()+`)"`) || !strings.Contains(logs.String(), `"to":"8 (`) {
		t.Errorf("the hook did not get the two active readings:\n%s", logs)
	}
	logs.Reset()
	postRefresh(t, mpzd, readOf(t, acRecords("", `serial="8" servers="beta,alpha"`)...), false)
	if strings.Contains(logs.String(), "the zone's active instructions changed") {
		t.Errorf("the hook ran for a refresh that changed nothing of them:\n%s", logs)
	}
}

func TestTheHookRunsAtEveryFirstLoad(t *testing.T) {
	asMPAgent(t)
	logs := captureZonesLog(t)
	records := acRecords("", `serial="7" servers="alpha,beta"`)
	mpzd := instrTestZone(t, "firstload.access.example.", records...)
	// the store already holds the copy's serial, as after a restart
	s := newStore(t)
	withStore(t, s)
	s.Note(mpzd.ZoneName, readOf(t, records...), nil)
	postRefresh(t, mpzd, mpzd.instructions(), true)
	if !strings.Contains(logs.String(), `"from":"none"`) {
		t.Errorf("the hook did not run at the first load:\n%s", logs)
	}
}

// Until S7 the readers act by the copy, whatever the store makes of it
// (plan S2): an edit at serial 0, one at the same serial and a lower serial
// are each acted on, as before S3, and an owner error is only shown.
func TestUntilEnforcedEveryCopyIsActedOn(t *testing.T) {
	asMPAgent(t)
	for _, c := range []struct{ name, before, after, ownerError string }{
		{"serial0", `servers="alpha,beta"`, `servers="alpha,beta" parentsync="agent"`, "serial 0 with two digests"},
		{"conflict", `serial="7" servers="alpha,beta"`, `serial="7" servers="alpha,beta" parentsync="agent"`, "serial 7 with two digests"},
		{"lower", `serial="7" servers="alpha,beta"`, `serial="6" servers="alpha,beta" parentsync="agent"`, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			logs := captureZonesLog(t)
			mpzd := instrTestZone(t, c.name+".follow.access.example.", acRecords("", c.before)...)
			s := newStore(t)
			withStore(t, s)
			before := mpzd.instructions()
			s.Note(mpzd.ZoneName, before, nil)
			setApex(t, mpzd, core.TypeHSYNCPARAM, `3600 IN HSYNCPARAM `+c.after)
			after := readOf(t, acRecords("", c.after)...)
			s.Note(mpzd.ZoneName, after, nil)
			postRefresh(t, mpzd, before, false)
			if got := instructionsFor(ZoneName(mpzd.ZoneName)); got == nil || got.Digest() != after.Digest() {
				t.Errorf("the readers act by %+v, want the copy", got)
			}
			if r := rolesForZone(ZoneName(mpzd.ZoneName)); r.ParentSync != core.HsyncParentSyncAgent {
				t.Errorf("parentsync %d, want the copy's agent", r.ParentSync)
			}
			if !strings.Contains(logs.String(), "the zone's active instructions changed") {
				t.Errorf("the hook did not run for the edit:\n%s", logs)
			}
			if st := s.Status(mpzd.ZoneName); !strings.HasPrefix(st.OwnerError, c.ownerError) || (c.ownerError == "") != (st.OwnerError == "") {
				t.Errorf("owner error %q, want %q", st.OwnerError, c.ownerError)
			}
		})
	}
}

// The auditor's identity check finds an ON record's label whatever the
// case of the identity asked for.
func TestAnAuditorIsFoundByItsIdentityInAnyCase(t *testing.T) {
	mpzd := instrTestZone(t, "auditorcase.access.example.", acRecords("ON", `serial="7" servers="alpha,beta" auditors="gamma"`)...)
	for _, id := range []string{acGamma, "Agent.GAMMA.example", "agent.gamma.example."} {
		if !mpzd.IsAuditorIdentity(id) {
			t.Errorf("%s is not found as the auditor gamma", id)
		}
	}
	if mpzd.IsAuditorIdentity(acBeta) {
		t.Errorf("%s, a server, is found as an auditor", acBeta)
	}
}

func TestARestartWithAStoredSerialHasGroupsAndPeersAfterTheFirstLoad(t *testing.T) {
	saved := tdns.Globals.App.Type
	tdns.Globals.App.Type = AppTypeMPAuditor
	t.Cleanup(func() { tdns.Globals.App.Type = saved })
	records := acRecords("", `serial="7" servers="alpha,beta"`)
	mpzd := instrTestZone(t, "restart.access.example.", records...)
	s := newStore(t)
	withStore(t, s)
	s.Note(mpzd.ZoneName, readOf(t, records...), nil) // stored before the restart

	pgm := NewProviderGroupManager(acAlpha)
	tm := &MPTransportBridge{agentRegistry: &AgentRegistry{ProviderGroupManager: pgm}}
	mpzd.EnsureMP()
	mpzd.MP.RefreshAnalysis = &ZoneRefreshAnalysis{ActiveBefore: mpzd.instructions(), FirstLoad: true}
	mpzd.PostRefresh(tm, nil)
	if pg := pgm.GetGroupForZone(ZoneName(mpzd.ZoneName)); pg == nil || !slices.Equal(pg.VotingMembers, []string{acAlpha, acBeta}) {
		t.Errorf("after a first load with the serial stored: group %+v, want alpha and beta", pg)
	}
}

func TestGroupsComeFromTheActiveReadingNotTheCopy(t *testing.T) {
	mpzd := instrTestZone(t, "groups.access.example.", acRecords("ON", `serial="7" servers="alpha,beta"`)...)
	s := newStore(t)
	withStore(t, s)
	activeAs(t, s, mpzd.ZoneName, readOf(t, acRecords("ON", `serial="8" servers="alpha,gamma"`)...))
	pgm := NewProviderGroupManager(acAlpha)
	pgm.RecomputeGroups()
	pg := pgm.GetGroupForZone(ZoneName(mpzd.ZoneName))
	if pg == nil || !slices.Equal(pg.VotingMembers, []string{acAlpha, acGamma}) {
		t.Errorf("group %+v; want the active serial's alpha and gamma, not the copy's alpha and beta", pg)
	}
}

func TestMPdataFollowsTheStepsSetsWithoutATransfer(t *testing.T) {
	asMPAgent(t)
	mpzd := instrTestZone(t, "mpdata.access.example.", acRecords("", `serial="7" servers="alpha,beta" signers="beta"`)...)
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: acAlpha})
	conf.onSetsChanged(mpzd, true)
	if mpzd.MP.MPdata == nil || mpzd.MP.MPdata.WeAreSigner {
		t.Fatalf("by the copy: MPdata %+v, want a server that does not sign", mpzd.MP.MPdata)
	}
	s := newStore(t)
	withStore(t, s)
	activeAs(t, s, mpzd.ZoneName, readOf(t, acRecords("", `serial="8" servers="alpha,beta" signers="alpha,beta"`)...))
	conf.onSetsChanged(mpzd, true) // no transfer: the copy is as it was
	if !mpzd.MP.MPdata.WeAreSigner || mpzd.MP.MPdata.OtherSigners != 1 {
		t.Errorf("after the sets changed: MPdata %+v, want a signer with one other", mpzd.MP.MPdata)
	}
}

func TestThePreRefreshReadersGetAReadingOfTheApex(t *testing.T) {
	served := instrTestZone(t, "prerefresh.access.example.", acRecords("", `serial="7" servers="alpha,beta" signers="beta"`)...)
	s := newStore(t)
	withStore(t, s)
	s.Note(served.ZoneName, served.instructions(), nil)
	incoming := zoneCopy(t, served.ZoneName, acRecords("", `serial="8" servers="alpha,beta" signers="alpha"`)...)
	wrapper := &MPZoneData{ZoneData: incoming, MP: &MPState{}, MPOptions: map[tdns.ZoneOption]bool{}}
	if wrapper.served() {
		t.Fatal("the incoming copy reads as the zone served")
	}
	wrapper.populateMPdata(&MultiProviderConf{Role: "agent", Identity: acAlpha}, wrapper.signingSet())
	if wrapper.MP.MPdata == nil || !wrapper.MP.MPdata.WeAreSigner {
		t.Errorf("the incoming copy's MPdata %+v; want alpha a signer, as the incoming copy says, not the store", wrapper.MP.MPdata)
	}
}

func TestAdmissionReadsTheActiveReading(t *testing.T) {
	mpzd := instrTestZone(t, "admission.access.example.", acRecords("ON", `serial="7" servers="alpha,beta"`)...)
	tm := &MPTransportBridge{TransportManager: &transport.TransportManager{LocalID: acAlpha}, getZone: tdns.Zones.Get}
	if ok, why := tm.isInHSYNC(acGamma, mpzd.ZoneName); ok {
		t.Fatalf("gamma, no role by the copy, was admitted (%s)", why)
	}
	s := newStore(t)
	withStore(t, s)
	activeAs(t, s, mpzd.ZoneName, readOf(t, acRecords("ON", `serial="8" servers="alpha,gamma"`)...))
	if ok, why := tm.isInHSYNC(acGamma, mpzd.ZoneName); !ok {
		t.Errorf("gamma, a server by the active serial, was refused: %s", why)
	}
	if ok, _ := tm.isInHSYNC(acBeta, mpzd.ZoneName); ok {
		t.Error("beta, no role by the active serial, was admitted by the copy")
	}
}

func TestApplyHsyncDiffGetsOnlyIdentitiesThatEnteredOrLeft(t *testing.T) {
	from := readOf(t, acRecords("ON", `serial="7" servers="alpha,beta,gamma"`)...)
	to := readOf(t, append(acRecords("", `serial="8" servers="alpha,beta"`), `3600 IN HSYNC3 ON delta agent.delta.example. .`)...)
	if got := recordsEntering(from, to); len(got) != 1 || got[0] != "agent.delta.example." {
		t.Errorf("entered %v, want delta only", got)
	}
	if got := recordsEntering(to, from); len(got) != 1 || got[0] != acGamma {
		t.Errorf("left %v, want gamma only", got)
	}
	// a change of roles alone enters and leaves nobody
	roles := readOf(t, acRecords("ON", `serial="9" servers="alpha" signers="beta,gamma"`)...)
	if e, l := recordsEntering(from, roles), recordsEntering(roles, from); len(e)+len(l) != 0 {
		t.Errorf("a change of roles alone: entered %v left %v", e, l)
	}
	if got := recordsEntering(nil, from); len(got) != 3 {
		t.Errorf("at a first load: entered %v, want every ON record", got)
	}
}

func TestCatchUpReasonsComeFromTheActiveChange(t *testing.T) {
	from := readOf(t, acRecords("ON", `serial="7" servers="alpha,beta"`)...)
	to := readOf(t, acRecords("ON", `serial="8" servers="alpha,beta,gamma"`)...)
	a := &ZoneRefreshAnalysis{}
	catchUpReasons(a, from, to, acGamma, true)
	if a.StandingBefore != standingNoRole || a.StandingAfter != standingVoting || !a.HsyncChanged {
		t.Errorf("gamma's standing %v -> %v, changed %v; want no role -> voting, changed", a.StandingBefore, a.StandingAfter, a.HsyncChanged)
	}
	if !slices.Equal(a.NewVoters, []AgentId{acGamma}) {
		t.Errorf("new voters %v, want gamma", a.NewVoters)
	}
}

func TestPeerRoleFiresForAProviderThatEntersAList(t *testing.T) {
	from := readOf(t, acRecords("", `serial="7" servers="alpha,beta" signers="alpha"`)...)
	to := readOf(t, acRecords("", `serial="8" servers="alpha,beta" signers="alpha,beta"`)...)
	a := &ZoneRefreshAnalysis{}
	catchUpReasons(a, from, to, acAlpha, true)
	// beta voted before and after; it entered signers= (a provider put back
	// in signers=, design 5.1), and that asks too
	if !slices.Equal(a.NewVoters, []AgentId{acBeta}) {
		t.Errorf("new voters %v, want beta, who entered signers=", a.NewVoters)
	}
}

func TestZoneChangedRunsAtAnActiveChange(t *testing.T) {
	asMPAgent(t)
	logs := captureZonesLog(t)
	mpzd := instrTestZone(t, "zonechanged.access.example.", acRecords("", `serial="8" servers="alpha,beta" parentsync="agent"`)...)
	mpzd.SetRuntimeOption(tdns.OptParentSync, true)
	lem := NewLeaderElectionManager(AgentId(acAlpha), time.Minute, func(ZoneName, string, map[string][]string) error { return nil })
	tm := &MPTransportBridge{agentRegistry: &AgentRegistry{LeaderElectionManager: lem}}
	mpzd.EnsureMP()
	mpzd.MP.RefreshAnalysis = &ZoneRefreshAnalysis{ActiveBefore: readOf(t, acRecords("", `serial="7" servers="alpha" parentsync="agent"`)...)}
	mpzd.PostRefresh(tm, nil)
	if !strings.Contains(logs.String(), "the zone's active instructions changed") {
		t.Fatalf("no hook at an active change:\n%s", logs)
	}
	lem.mu.RLock()
	_, elected := lem.elections[ZoneName(mpzd.ZoneName)]
	lem.mu.RUnlock()
	if !elected {
		t.Error("the zone's election was not checked (zoneChanged) at the active change")
	}
}

func TestParentsyncFollowsTheStepsSetsBothWays(t *testing.T) {
	asMPAgent(t)
	mpzd := instrTestZone(t, "parentsync.access.example.", acRecords("", `serial="7" servers="alpha,beta"`)...)
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: acAlpha})
	s := newStore(t)
	withStore(t, s)
	activeAs(t, s, mpzd.ZoneName, readOf(t, acRecords("", `serial="8" servers="alpha,beta" parentsync="agent"`)...))
	conf.onSetsChanged(mpzd, false)
	if !mpzd.Options[tdns.OptParentSync] {
		t.Fatal("the sets say parentsync=agent and the option is off (the copy says owner)")
	}
	activeAs(t, s, mpzd.ZoneName, readOf(t, acRecords("", `serial="9" servers="alpha,beta"`)...))
	conf.onSetsChanged(mpzd, false)
	if mpzd.Options[tdns.OptParentSync] {
		t.Error("the sets say parentsync=owner and the option is still on")
	}
}

func TestNsmgmtAndParentsyncDoNotChangeAtTheActivation(t *testing.T) {
	asMPAgent(t)
	fromRecords := acRecords("", `serial="7" servers="alpha,beta"`)
	mpzd := instrTestZone(t, "nochange.access.example.", fromRecords...)
	s := newStore(t)
	withStore(t, s)
	from, to := readOf(t, fromRecords...), readOf(t, acRecords("", `serial="8" servers="alpha,beta" nsmgmt="agent" parentsync="agent"`)...)
	s.Note(mpzd.ZoneName, from, nil)
	enforced(t, s, mpzd.ZoneName)
	// held as S19 and S20 will let it be: the judge refuses both kinds until
	// their steps are built (S4)
	if err := s.update(mpzd.ZoneName, func(z *zoneSerials) error {
		z.Held = append(z.Held, heldSerial{SerialDigest: sd(to), Reading: to})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(mpzd.ZoneName, Thaw{From: sd(from), To: sd(to)}); err != nil {
		t.Fatal(err)
	}
	// a transition at step 0: the parts keep the sets they hold, N's
	r := mpzd.roles()
	if r.NSmgmt != core.HsyncNSmgmtOWNER || r.ParentSync != core.HsyncParentSyncOwner {
		t.Errorf("at the activation, before a step: nsmgmt %d parentsync %d, want the held owner, owner", r.NSmgmt, r.ParentSync)
	}
	conf := &Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&MultiProviderConf{Role: "agent", Identity: acAlpha})
	conf.onSetsChanged(mpzd, false)
	if mpzd.Options[tdns.OptParentSync] {
		t.Error("the parentsync option followed the activation, before a step")
	}
	if p := mpzd.getEditPolicy(); p.NSmgmt != core.HsyncNSmgmtOWNER {
		t.Errorf("the edit policy's nsmgmt %d followed the activation", p.NSmgmt)
	}
}

func TestRolesFromTheReadingAgreeWithTodaysFlags(t *testing.T) {
	for _, c := range []struct {
		name, param           string
		server, signer, voter bool
	}{
		{"signer", `servers="beta" signers="alpha"`, false, true, true},
		{"server", `servers="alpha" signers="beta"`, true, false, true},
		{"both", `servers="alpha" signers="alpha"`, true, true, true},
		{"auditor", `servers="beta" auditors="alpha"`, false, false, false},
		{"no role", `servers="beta" signers="beta"`, false, false, false},
		{"unsigned", `servers="alpha,beta"`, true, false, true},
		{"no HSYNCPARAM", ``, true, false, true}, // legacy: every ON record votes
	} {
		in := readOf(t, acRecords("", c.param)...)
		r := rolesFor(in, in, 0)
		_, voting := participantsOf(in)
		if has(r.Servers, "alpha") != c.server || has(r.Signing, "alpha") != c.signer || isAmong(voting, acAlpha) != c.voter {
			t.Errorf("%s: server %v signer %v voter %v; want %v %v %v", c.name,
				has(r.Servers, "alpha"), has(r.Signing, "alpha"), isAmong(voting, acAlpha), c.server, c.signer, c.voter)
		}
	}
}

func TestWithATransitionAndNoStepTheSetsAreThoseHeld(t *testing.T) {
	from := readOf(t, acRecords("ON", `serial="7" servers="alpha,beta" signers="alpha" nsmgmt="agent"`)...)
	to := readOf(t, acRecords("ON", `serial="8" servers="alpha,gamma" signers="gamma"`)...)
	got, want := rolesFor(from, to, 0), rolesFor(from, from, 0)
	if !slices.Equal(got.Servers, want.Servers) || !slices.Equal(got.Signing, want.Signing) || got.NSmgmt != want.NSmgmt {
		t.Errorf("at step 0 of 7 -> 8: %+v, want 7's sets %+v", got, want)
	}
}

func TestTheSetsNameEachProviderByLabelAndIdentity(t *testing.T) {
	in := readOf(t, acRecords("ON", `serial="7" servers="alpha,beta,nobody" signers="gamma"`)...)
	r := rolesFor(in, in, 0)
	want := []Provider{{"alpha", acAlpha}, {"beta", acBeta}, {"nobody", ""}}
	if !slices.Equal(r.Servers, want) || !slices.Equal(r.Signing, []Provider{{"gamma", acGamma}}) {
		t.Errorf("servers %v signing %v; want %v and gamma", r.Servers, r.Signing, want)
	}
}

func TestEveryLabelResolverReadsTheSetsNotTheRecords(t *testing.T) {
	// The copy names beta a signer; the active serial names gamma.
	mpzd := instrTestZone(t, "resolvers.access.example.", acRecords("ON", `serial="7" servers="alpha" signers="alpha,beta"`)...)
	s := newStore(t)
	withStore(t, s)
	activeAs(t, s, mpzd.ZoneName, readOf(t, acRecords("ON", `serial="8" servers="alpha" signers="alpha,gamma"`)...))
	zone := ZoneName(mpzd.ZoneName)
	for name, ok := range map[string]bool{
		"checkDNSKEYPolicy takes gamma's DNSKEY": func() bool { refused, _ := mpzd.checkDNSKEYPolicy(acGamma); return !refused }(),
		"checkDNSKEYPolicy refuses beta's":       func() bool { refused, _ := mpzd.checkDNSKEYPolicy(acBeta); return refused }(),
		"signingAgents names gamma, not beta": func() bool {
			sa := signingAgents(zone, []AgentId{acBeta, acGamma})
			return sa[acGamma] && !sa[acBeta]
		}(),
		"signingPeers names gamma":            slices.Equal(signingPeers(zone, acAlpha), []AgentId{acGamma}),
		"identitiesByLabel resolves gamma":    mpzd.identitiesByLabel()["gamma"] == acGamma,
		"the signing labels are alpha, gamma": slices.Equal(mpzd.signingLabels(), []string{"alpha", "gamma"}),
	} {
		if !ok {
			t.Errorf("%s: no", name)
		}
	}
}

func TestAProviderWhoseRemovalIsUnderWayIsResolvedThroughItsStoredIdentity(t *testing.T) {
	mpzd := instrTestZone(t, "removal.access.example.", acRecords("", `serial="7" servers="alpha" signers="alpha,beta"`)...)
	s := newStore(t)
	withStore(t, s)
	// the active serial lists beta in signers= with no ON record for it,
	// and beta's removal is under way
	activeAs(t, s, mpzd.ZoneName, readOf(t, `3600 IN HSYNC3 ON alpha `+acAlpha+` .`, `3600 IN HSYNCPARAM serial="8" servers="alpha" signers="alpha,beta"`))
	if err := s.update(mpzd.ZoneName, func(z *zoneSerials) error {
		z.Removals = []Removal{{Label: "beta", Identity: acBeta, Step: 2}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := mpzd.roles().Signing; !slices.Contains(got, Provider{"beta", acBeta}) {
		t.Errorf("signing %v: beta is not resolved through its removal", got)
	}
	if label, ok := mpzd.labelOf(acBeta); !ok || label != "beta" {
		t.Errorf("beta's label %q %v, want beta through its removal", label, ok)
	}
}

func TestEveryDecisionFollowsTheActiveSerialNotTheCopy(t *testing.T) {
	asMPAgent(t)
	mpzd := instrTestZone(t, "decisions.access.example.", acRecords("ON", `serial="7" servers="alpha,beta" auditors="gamma"`)...)
	s := newStore(t)
	withStore(t, s)
	activeAs(t, s, mpzd.ZoneName, readOf(t, acRecords("ON", `serial="8" servers="alpha,gamma" auditors="beta" pubkey`)...))
	zone := ZoneName(mpzd.ZoneName)
	for name, ok := range map[string]bool{
		"votesInZone gamma":           votesInZone(zone, acGamma),
		"votesInZone not beta":        !votesInZone(zone, acBeta),
		"VotingMembersForZone":        slices.Equal(VotingMembersForZone(zone), []AgentId{acAlpha, acGamma}),
		"AuditorsForZone":             slices.Equal(AuditorsForZone(zone), []AgentId{acBeta}),
		"mayHoldZoneSig0Key gamma":    mayHoldZoneSig0Key(zone, acGamma),
		"mayHoldZoneSig0Key not beta": !mayHoldZoneSig0Key(zone, acBeta),
		"pubkey":                      mpzd.hasPubkey(),
		"publishLocations at-ns":      slices.Contains(publishLocations(zone), "at-ns"),
		"GetAuditors":                 slices.Equal(mpzd.GetAuditors(), []string{"beta"}),
		"expected identities":         !slices.Contains(expectedHSYNC3Identities(mpzd.ZoneName), acBeta),
		"mplist servers":              slices.Equal(MPZoneInfoFromMPZoneData(mpzd).Servers, []string{"alpha", "gamma"}),
	} {
		if !ok {
			t.Errorf("%s: by the copy, not the active serial", name)
		}
	}
}

func TestAnOffRecordGivesNoLabel(t *testing.T) {
	mpzd := instrTestZone(t, "off.access.example.", acRecords("OFF", `serial="7" servers="alpha" signers="alpha,gamma"`)...)
	if matched, label, _ := mpzd.matchHsyncIdentity([]string{acGamma}); matched {
		t.Errorf("an OFF record gave gamma the label %q", label)
	}
	if refused, why := mpzd.checkDNSKEYPolicy(acGamma); !refused || !strings.Contains(why, "not found") {
		t.Errorf("checkDNSKEYPolicy took a DNSKEY from gamma, whose record is OFF (%v, %q)", refused, why)
	}
}

func TestTheAuditorsExpectedIdentitiesSkipOffRecords(t *testing.T) {
	mpzd := instrTestZone(t, "expected.access.example.", acRecords("OFF", `serial="7" servers="alpha" auditors="beta"`)...)
	if got := expectedHSYNC3Identities(mpzd.ZoneName); !slices.Equal(got, []string{acAlpha}) {
		t.Errorf("expected %v; want alpha alone, not the auditor beta nor gamma, whose record is OFF", got)
	}
}

func TestACopyWithoutAReadingKeepsTheLastOne(t *testing.T) {
	logs := captureZonesLog(t)
	good := readOf(t, acRecords("", `serial="7" servers="alpha,beta"`)...)
	readingOf(apexOf(t, acRecords("", `serial="7" servers="alpha,beta"`)...))
	twice := apexOf(t, append(acRecords("", `serial="7" servers="alpha,beta"`), `3600 IN HSYNCPARAM serial="8" servers="alpha"`)...)
	for i := 0; i < 2; i++ {
		if got := readingOf(twice); got == nil || got.Digest() != good.Digest() {
			t.Fatalf("a copy with two HSYNCPARAM records reads %+v, want the last good reading", got)
		}
	}
	if n := strings.Count(logs.String(), "keeping the last"); n != 1 {
		t.Errorf("logged %d times, want once:\n%s", n, logs)
	}
	lastGood.Delete(instrZone)
	noReading.Delete(instrZone)
}

func TestLabelsAreResolvedThroughTheReading(t *testing.T) {
	in := readOf(t, `3600 IN HSYNC3 ON alpha AGENT.Alpha.Example. .`, `3600 IN HSYNC3 OFF gamma `+acGamma+` .`, `3600 IN HSYNCPARAM servers="alpha"`)
	if label, ok := in.labelOf("agent.alpha.example"); !ok || label != "alpha" {
		t.Errorf("alpha's identity in another case and without the dot: %q %v", label, ok)
	}
	if id := in.identityOf("alpha."); id != acAlpha {
		t.Errorf("alpha. resolves to %q", id)
	}
	if _, ok := in.labelOf(acGamma); ok {
		t.Error("an OFF record's identity resolved to a label")
	}
}

// tdns asks the agent whether the agents sync a zone's delegation (P3), and
// the agent answers by the step's sets, not by the zone's copy.
func TestTdnsAsksTheAgentForParentsync(t *testing.T) {
	mpzd := instrTestZone(t, "tdnsasks.access.example.", acRecords("", `serial="7" servers="alpha,beta"`)...)
	conf := &Config{Config: &tdns.Config{}}
	conf.Config.Internal.StopCh = make(chan struct{})
	t.Cleanup(func() { close(conf.Config.Internal.StopCh) })
	mp := &MultiProviderConf{Role: "agent", Identity: acAlpha}
	conf.SetMpConfig(mp)
	prev := instrStore.Load()
	t.Cleanup(func() {
		tdns.RegisterParentSyncAgentFunc(nil)
		instrStore.Store(prev)
	})
	if err := conf.initMPAgent(mp); err != nil {
		t.Fatalf("initMPAgent: %v", err)
	}
	zone := tdns.ZoneName(mpzd.ZoneName)
	if tdns.ZoneHasParentSyncAgent(zone) {
		t.Fatal("parentsync=agent before the instructions say so")
	}
	activeAs(t, conf.InternalMp.Instructions, mpzd.ZoneName, readOf(t, acRecords("", `serial="8" servers="alpha,beta" parentsync="agent"`)...))
	if !tdns.ZoneHasParentSyncAgent(zone) {
		t.Error("tdns read its copy (parentsync=owner), not the agent's sets (agent)")
	}
}
