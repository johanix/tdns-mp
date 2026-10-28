/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	tdnscli "github.com/johanix/tdns/v2/cli"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// parentSyncCLI serves agent as the "agent" role's management API and
// returns a function that runs "tdns-mpcli agent parentsync <args>" against
// it: the agent tree under a root with the persistent --zone flag, as
// cmd/mpcli builds it. The function returns what the command printed and the
// error it ended with.
func parentSyncCLI(t *testing.T, agent http.HandlerFunc) func(args ...string) (string, error) {
	t.Helper()
	return agentCLI(t, agent, "agent", "parentsync")
}

// agentCLI is parentSyncCLI for any of the agent's commands: each run's
// arguments follow prefix.
func agentCLI(t *testing.T, agent http.HandlerFunc, prefix ...string) func(args ...string) (string, error) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/agent", agent)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	key := tdnscli.GetClientKeyFromParent("agent")
	old, had := tdns.Globals.ApiClients[key]
	tdns.Globals.ApiClients[key] = tdns.NewClient(key, srv.URL, "test", "X-API-Key", "insecure")
	t.Cleanup(func() {
		if had {
			tdns.Globals.ApiClients[key] = old
		} else {
			delete(tdns.Globals.ApiClients, key)
		}
		tdns.Globals.Zonename = ""
	})

	return func(args ...string) (string, error) {
		root := &cobra.Command{Use: "tdns-mpcli"}
		root.PersistentFlags().StringVarP(&tdns.Globals.Zonename, "zone", "z", "", "zone name")
		root.AddCommand(NewAgentTree("agent", "agent"))
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(append(slices.Clone(prefix), args...))
		err := root.Execute()
		return out.String(), err
	}
}

// parentSyncTestAgent is the management handler of a real agent with the
// identity id: it serves zone, with two nameservers and its KEY at the apex,
// holds the zone's active SIG(0) key, and has an election manager. It has no
// peers, no resolver and no parent. Returns the handler and the key's id.
func parentSyncTestAgent(t *testing.T, id, zone string) (http.HandlerFunc, uint16) {
	t.Helper()
	conf, hdb, keyid := parentSyncTestConf(t, id, zone)
	return conf.APIagent(t.Context(), nil, hdb), keyid
}

// parentSyncTestConf is that agent before its handler is made, for a test
// that gives it more: records are further records of the zone, one a line.
func parentSyncTestConf(t *testing.T, id, zone string, records ...string) (*tdnsmp.Config, *tdnsmp.HsyncDB, uint16) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "keys.db")
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatalf("create db file: %v", err)
	}
	kdb, err := tdns.NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	hdb := tdnsmp.NewHsyncDB(kdb)
	if _, err := hdb.Sig0KeyMgmt(nil, tdns.KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "generate",
		Zone:       zone,
		Keyname:    zone,
		Algorithm:  dns.ED25519,
		State:      tdns.Sig0StateActive,
		Creator:    "test",
	}); err != nil {
		t.Fatalf("generate the SIG(0) key: %v", err)
	}
	sak, err := hdb.GetSig0Keys(zone, tdns.Sig0StateActive)
	if err != nil || len(sak.Keys) != 1 {
		t.Fatalf("active SIG(0) keys for %s: %v, err %v", zone, sak, err)
	}

	text := fmt.Sprintf("%s 3600 IN SOA ns1.alpha.example. hostmaster.%s 1 7200 1800 604800 7200\n"+
		"%s 3600 IN NS ns1.alpha.example.\n%s 3600 IN NS ns1.bravo.example.\n%s\n",
		zone, zone, zone, zone, sak.Keys[0].KeyRR.String())
	for _, rr := range records {
		text += rr + "\n"
	}
	zd := &tdns.ZoneData{
		ZoneName:  zone,
		ZoneStore: tdns.MapZone,
		ZoneType:  tdns.Primary,
		Logger:    log.New(io.Discard, "", 0),
		Options:   map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
	}
	if _, _, err := zd.ReadZoneData(text, true); err != nil {
		t.Fatalf("ReadZoneData(%s): %v", zone, err)
	}
	tdns.Zones.Set(zone, zd)
	t.Cleanup(func() {
		tdns.Zones.Remove(zone)
		tdnsmp.Zones.Invalidate(zone)
	})
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.StopPublisher)

	conf := &tdnsmp.Config{Config: &tdns.Config{}}
	conf.SetMpConfig(&tdnsmp.MultiProviderConf{Identity: id})
	conf.InternalMp.LeaderElectionManager = tdnsmp.NewLeaderElectionManager(tdnsmp.AgentId(id), time.Hour,
		func(tdnsmp.ZoneName, string, map[string][]string) error { return nil })

	return conf, hdb, sak.Keys[0].KeyId
}

func wantLines(t *testing.T, what, out string, lines ...string) {
	t.Helper()
	for _, want := range lines {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("%s lacks the line %q:\n%s", what, want, out)
		}
	}
}

// wantNoControls: nothing in out but its newlines would reach a terminal as
// a control or format character.
func wantNoControls(t *testing.T, what, out string) {
	t.Helper()
	for _, r := range out {
		if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			t.Errorf("%s printed control character %U:\n%q", what, r, out)
		}
	}
}

// Each of the four subcommands posts the command the agent's handler
// switches on: the handler answers from that command's own branch. A command
// name changed on one side only gets the handler's "Unknown agent command",
// from which none of these answers can come.
func TestParentSyncSubcommandsPostWhatTheAgentSwitchesOn(t *testing.T) {
	const id, zone = "agent.alpha.example.", "posts.parentsync.example."
	agent, keyid := parentSyncTestAgent(t, id, zone)
	run := parentSyncCLI(t, agent)

	// Not the leader yet: the bootstrap is refused.
	if out, err := run("bootstrap", "-z", zone); err == nil ||
		!strings.Contains(err.Error(), "not the delegation sync leader for "+zone) {
		t.Errorf("bootstrap on an agent that does not lead: error %v, output %q; want the handler's refusal", err, out)
	}

	// No resolver in this agent: the inquiry gets as far as asking for it.
	if out, err := run("inquire", "-z", zone); err == nil ||
		!strings.Contains(err.Error(), "IMR engine not available") {
		t.Errorf("inquire on an agent without a resolver: error %v, output %q; want the handler's refusal", err, out)
	}

	out, err := run("status", "-z", zone)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines(t, "status before the election", out,
		"Parent sync status for zone "+zone,
		"  leader:         none")

	// No peers and no provider group: the agent elects itself at once.
	out, err = run("election", "-z", zone)
	if err != nil {
		t.Fatalf("election: %v", err)
	}
	wantLines(t, "election", out, "Election started for zone "+zone+" with 0 peers")

	// The leader's bootstrap is accepted. It runs in the agent, and stops
	// with the test: this agent has no resolver to reach a parent with.
	out, err = run("bootstrap", "-z", zone)
	if err != nil {
		t.Fatalf("bootstrap on the leader: %v", err)
	}
	wantLines(t, "bootstrap", out,
		fmt.Sprintf("Bootstrap triggered for zone %s (keyid %d), running async", zone, keyid))
}

// The status command prints what the agent's handler reports of the zone:
// the leader before and after an election, the SIG(0) key, the KEY at the
// apex and the zone's nameservers.
func TestParentSyncStatusShowsWhatTheAgentReports(t *testing.T) {
	const id, zone = "agent.alpha.example.", "status.parentsync.example."
	agent, keyid := parentSyncTestAgent(t, id, zone)
	run := parentSyncCLI(t, agent)

	out, err := run("status", "-z", zone)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines(t, "status", out,
		"Parent sync status for zone "+zone,
		"  leader:         none",
		"  election term:  0",
		fmt.Sprintf("  SIG(0) key:     ED25519, key id %d", keyid),
		`  parent state:   0 (not asked yet, or the parent answered "Request Malformed")`,
		"  KEY at apex:    published",
		"  CDS at apex:    not published",
		"  CSYNC at apex:  not published",
		"  zone:           not signed",
		"  parent zone:    unknown (the agent's DSYNC lookup found nothing)",
		"Nameservers of the zone:",
		"  ns1.alpha.example.",
		"  ns1.bravo.example.")
	if !strings.Contains(out, "  KEY record:     "+zone+" ") || !strings.Contains(out, " IN KEY ") {
		t.Errorf("status does not show the KEY record on one line:\n%s", out)
	}
	for _, absent := range []string{"Peers:", "Sync schemes the parent advertises:", "KEY record under the nameservers:"} {
		if strings.Contains(out, absent) {
			t.Errorf("status has a %q section and the agent reported nothing for it:\n%s", absent, out)
		}
	}

	if _, err := run("election", "-z", zone); err != nil {
		t.Fatalf("election: %v", err)
	}
	out, err = run("status", "-z", zone)
	if err != nil {
		t.Fatalf("status after the election: %v", err)
	}
	// The lease is the manager's hour, less the moment between the election
	// and the report.
	if !strings.Contains(out, "  leader:         "+id+" (this agent), lease expires in 59m") {
		t.Errorf("status after the election does not show this agent as the leader with its lease:\n%s", out)
	}
}

// The peers of the report, from the agent's real handler. The zone names
// three other providers in HSYNC3 and gives each a role in HSYNCPARAM, and
// the agent's transport holds them in three states. The report names each
// peer's state, and the Peers table shows the names.
func TestParentSyncStatusNamesEachPeersState(t *testing.T) {
	const id, zone = "agent.alpha.example.", "peers.parentsync.example."
	conf, hdb, _ := parentSyncTestConf(t, id, zone,
		zone+" 3600 IN HSYNC3 ON alpha agent.alpha.example. .",
		zone+" 3600 IN HSYNC3 ON bravo agent.bravo.example. .",
		zone+" 3600 IN HSYNC3 ON charlie agent.charlie.example. .",
		zone+" 3600 IN HSYNC3 ON delta agent.delta.example. .",
		zone+` 3600 IN HSYNCPARAM servers="alpha,bravo,charlie,delta" signers="alpha" nsmgmt="agent" parentsync="agent" serial="1"`)

	ar := conf.NewAgentRegistry()
	peers := transport.NewPeerRegistry()
	ar.TransportManager = &transport.TransportManager{PeerRegistry: peers}
	conf.InternalMp.AgentRegistry = ar
	// bravo is reached over DNS, and a beat got through a moment ago.
	bravo := peers.GetOrCreate("agent.bravo.example.")
	bravo.SetMechanismState(transport.MechanismDNS, transport.PeerStateOperational, "test")
	bravo.SetMechanismLastBeatSent(transport.MechanismDNS, time.Now())
	// charlie was reached over the API; the last beat that got through is
	// ten minutes old.
	charlie := peers.GetOrCreate("agent.charlie.example.")
	charlie.SetMechanismState(transport.MechanismAPI, transport.PeerStateOperational, "test")
	charlie.SetMechanismLastBeatSent(transport.MechanismAPI, time.Now().Add(-10*time.Minute))
	// delta is in the zone, and the transport has not heard of it.

	agent := conf.APIagent(t.Context(), nil, hdb)
	states := func() map[tdnsmp.AgentId]string {
		t.Helper()
		body, err := json.Marshal(AgentMgmtPost{Command: "parentsync-status", Zone: zone})
		if err != nil {
			t.Fatalf("marshal the request: %v", err)
		}
		rec := httptest.NewRecorder()
		agent(rec, httptest.NewRequest(http.MethodPost, "/agent", bytes.NewReader(body)))
		var amr AgentMgmtResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &amr); err != nil {
			t.Fatalf("the answer does not parse: %v: %s", err, rec.Body.String())
		}
		if amr.Error {
			t.Fatalf("the handler answered with an error: %s", amr.ErrorMsg)
		}
		report, err := parentSyncStatusFromResponse(&amr)
		if err != nil {
			t.Fatalf("the report: %v", err)
		}
		got := map[tdnsmp.AgentId]string{}
		for _, p := range report.Peers {
			got[p.Identity] = p.State
		}
		return got
	}
	want := map[tdnsmp.AgentId]string{
		"agent.bravo.example.":   "OPERATIONAL",
		"agent.charlie.example.": "INTERRUPTED",
		"agent.delta.example.":   "NEEDED",
	}
	if got := states(); !maps.Equal(got, want) {
		t.Errorf("the report gives the peers' states as %q, want %q", got, want)
	}

	run := parentSyncCLI(t, agent)
	out, err := run("status", "-z", zone)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines(t, "status", out,
		"Peers:",
		"  State         Transport  Operational  Identity",
		"  OPERATIONAL   DNS        yes          agent.bravo.example.",
		"  INTERRUPTED   -          no           agent.charlie.example.",
		"  NEEDED        -          no           agent.delta.example.")

	// A state the table has no name for goes out by its number, and the
	// column is not left empty. No state is without a name today, so the
	// table loses one for the moment.
	needed := AgentStateToString[tdnsmp.AgentStateNeeded]
	delete(AgentStateToString, tdnsmp.AgentStateNeeded)
	t.Cleanup(func() { AgentStateToString[tdnsmp.AgentStateNeeded] = needed })
	if got := states()["agent.delta.example."]; got != "STATE1" {
		t.Errorf("a state without a name is reported as %q, want STATE1", got)
	}
	out, err = run("status", "-z", zone)
	if err != nil {
		t.Fatalf("status with a state that has no name: %v", err)
	}
	wantLines(t, "status with a state that has no name", out,
		"  STATE1        -          no           agent.delta.example.")
}

// The parts of the report that need a resolver, a parent and peers, which
// the agent of the tests above has not got. The report is built in the
// handler's own types and written the way the handler writes its response.
// Names in it come from peers and from the parent's DNS: a control character
// among them is printed as an escape.
func TestParentSyncStatusPrintsEveryPartOfTheReport(t *testing.T) {
	const zone = "full.parentsync.example."
	checked := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	report := tdnsmp.ParentSyncStatus{
		Zone:            zone,
		Leader:          "agent.bravo.example.",
		LeaderExpiry:    checked.Add(47*time.Minute + 12*time.Second),
		ElectionTerm:    4,
		KeyAlgorithm:    "ED25519",
		KeyID:           4711,
		KeyRR:           zone + "\t3600\tIN\tKEY\t512 3 15 q83vEjRWeJA=",
		ApexPublished:   true,
		ParentState:     4,
		ParentStateName: "Trusted",
		ChildNS:         []string{"ns1.alpha.example.", "ns1.bravo.example."},
		KeyPublication: map[string]bool{
			tdnsmp.Sig0KeyOwnerName(zone, "ns1.bravo.example."): false,
			tdnsmp.Sig0KeyOwnerName(zone, "ns1.alpha.example."): true,
		},
		LastChecked: checked,
		ParentZone:  "parentsync.example.",
		SyncSchemes: []tdnsmp.DsyncSchemeInfo{
			{Scheme: "UPDATE", Type: "ANY", Target: "updates.parentsync.example.", Port: 5354},
			{Scheme: "NOTIFY", Type: "CDS", Target: "scanner\x1b[2J.parentsync.example.", Port: 5353},
		},
		ActiveScheme:   "UPDATE",
		CdsPublished:   true,
		CsyncPublished: false,
		ZoneSigned:     true,
		Peers: []tdnsmp.PeerSyncInfo{
			{Identity: "agent.bravo.example.", State: "OPERATIONAL", Transport: "DNS", Operational: true},
			{Identity: "agent.charlie\x1b]0;retitled\x07.example.", State: "NEEDED", Transport: "-", Operational: false},
		},
	}
	agent := func(report tdnsmp.ParentSyncStatus) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			resp := tdnsmp.AgentMgmtResponse{Identity: "agent.alpha.example.", Time: checked, Data: report}
			if err := json.NewEncoder(w).Encode(tdns.SanitizeForJSON(resp)); err != nil {
				t.Errorf("encode the response: %v", err)
			}
		}
	}

	out, err := parentSyncCLI(t, agent(report))("status", "-z", zone)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines(t, "status", out,
		"Parent sync status for zone "+zone,
		"  checked:        2026-10-12 12:00:00 UTC",
		"  leader:         agent.bravo.example., lease expires in 47m12s",
		"  election term:  4",
		"  SIG(0) key:     ED25519, key id 4711",
		"  KEY record:     "+zone+" 3600 IN KEY 512 3 15 q83vEjRWeJA=",
		"  parent state:   Trusted (4), as last recorded",
		"  KEY at apex:    published",
		"  CDS at apex:    published",
		"  CSYNC at apex:  not published",
		"  zone:           signed",
		"  parent zone:    parentsync.example.",
		"  scheme in use:  UPDATE",
		"Sync schemes the parent advertises:",
		"  Scheme    Type    Port   Target",
		"  UPDATE    ANY     5354   updates.parentsync.example.",
		`  NOTIFY    CDS     5353   scanner\x1b[2J.parentsync.example.`,
		"KEY record under the nameservers:",
		"  _sig0key."+zone+"_signal.ns1.alpha.example.  published",
		"  _sig0key."+zone+"_signal.ns1.bravo.example.  not published",
		"Peers:",
		"  State         Transport  Operational  Identity",
		"  OPERATIONAL   DNS        yes          agent.bravo.example.",
		`  NEEDED        -          no           agent.charlie\x1b]0;retitled\x07.example.`)
	wantNoControls(t, "status", out)

	// The agent's own names for a code or a state are escaped like the
	// names from outside: the command prints what a daemon sent. The peer's
	// state here is one control byte, which is how an agent sent it before
	// the state went out by its name.
	odd := report
	odd.KeyAlgorithm = "ED25519\x1b[31m"
	odd.ParentStateName = "Trusted\x07"
	odd.ActiveScheme = "UPDATE\u202e"
	odd.SyncSchemes = []tdnsmp.DsyncSchemeInfo{
		{Scheme: "UPDATE\x08", Type: "ANY\x1b[1m", Target: "updates.parentsync.example.", Port: 5354},
	}
	odd.Peers = []tdnsmp.PeerSyncInfo{
		{Identity: "agent.bravo.example.", State: "\x07", Transport: "DNS\u009b1m", Operational: true},
	}
	out, err = parentSyncCLI(t, agent(odd))("status", "-z", zone)
	if err != nil {
		t.Fatalf("status with control characters in the agent's own names: %v", err)
	}
	wantLines(t, "status with control characters in the agent's own names", out,
		`  SIG(0) key:     ED25519\x1b[31m, key id 4711`,
		`  parent state:   Trusted\x07 (4), as last recorded`,
		`  scheme in use:  UPDATE\u202e`,
		`  UPDATE\x08  ANY\x1b[1m  5354   updates.parentsync.example.`,
		`  \x07          DNS\u009b1m  yes          agent.bravo.example.`)
	wantNoControls(t, "status with control characters in the agent's own names", out)

	// The same name on the line for a key the parent was never asked about.
	odd.ParentState = 0
	out, err = parentSyncCLI(t, agent(odd))("status", "-z", zone)
	if err != nil {
		t.Fatalf("status with a control character in the name of state 0: %v", err)
	}
	wantLines(t, "status with a control character in the name of state 0", out,
		`  parent state:   0 (not asked yet, or the parent answered "Trusted\a")`)
	wantNoControls(t, "status with a control character in the name of state 0", out)

	// A lease that has run out is no leader, whoever held it.
	report.LeaderExpiry = checked.Add(-3 * time.Minute)
	out, err = parentSyncCLI(t, agent(report))("status", "-z", zone)
	if err != nil {
		t.Fatalf("status with an expired lease: %v", err)
	}
	wantLines(t, "status with an expired lease", out,
		"  leader:         none (the lease of agent.bravo.example. has expired)")
}

// The zone's catch-up: whether it is caught up and whom it waits for, and a
// row per voting member, with why an answer is not complete or a request
// failed.
func TestParentSyncStatusShowsTheCatchUp(t *testing.T) {
	const zone = "catchup.parentsync.example."
	checked := time.Date(2026, 10, 12, 15, 4, 0, 0, time.UTC)
	asked, answered := checked.Add(5*time.Second), checked.Add(6*time.Second)
	report := tdnsmp.ParentSyncStatus{
		Zone:        zone,
		LastChecked: checked,
		CatchUp: &tdnsmp.CatchUpStatus{
			WaitingFor: "agent.bravo.example., agent.charlie.example.",
			Peers: []tdnsmp.CatchUpPeerStatus{
				{Identity: "agent.alpha.example.", Answer: "complete", Asked: asked, Answered: answered, Reason: "start"},
				{Identity: "agent.bravo.example.", Answer: "not complete", Asked: asked, Answered: answered, Reason: "start", Note: "no-inventory"},
				{Identity: "agent.charlie.example.", Answer: "none", Asked: asked, Reason: "peer-start", Note: "refused"},
			},
		},
	}
	agent := func(report tdnsmp.ParentSyncStatus) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			resp := tdnsmp.AgentMgmtResponse{Identity: "agent.delta.example.", Time: checked, Data: report}
			if err := json.NewEncoder(w).Encode(tdns.SanitizeForJSON(resp)); err != nil {
				t.Errorf("encode the response: %v", err)
			}
		}
	}
	out, err := parentSyncCLI(t, agent(report))("status", "-z", zone)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines(t, "status", out,
		"  catch-up:       not caught up, waiting for agent.bravo.example., agent.charlie.example.",
		"Catch-up, per voting member:",
		"  Answer        Asked     Answered  Reason      Identity",
		"  complete      15:04:05  15:04:06  start       agent.alpha.example.",
		"  not complete  15:04:05  15:04:06  start       agent.bravo.example.  (no-inventory)",
		"  none          15:04:05  -         peer-start  agent.charlie.example.  (refused)")

	report.CatchUp = &tdnsmp.CatchUpStatus{CaughtUp: true}
	out, err = parentSyncCLI(t, agent(report))("status", "-z", zone)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines(t, "status, caught up", out, "  catch-up:       caught up")

	report.CatchUp = &tdnsmp.CatchUpStatus{NotVoting: true}
	out, err = parentSyncCLI(t, agent(report))("status", "-z", zone)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines(t, "status, not voting", out, "  catch-up:       none: this agent does not vote in the zone, and asks nothing")

	// the leader's sync is held, and the DS set is unknown
	report.CatchUp = &tdnsmp.CatchUpStatus{WaitingFor: "agent.bravo.example."}
	report.ParentSync = "held until the zone is caught up"
	report.DSSet = "unknown, waiting for agent.bravo.example. (not spoken)"
	out, err = parentSyncCLI(t, agent(report))("status", "-z", zone)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines(t, "status, held", out,
		"  catch-up:       not caught up, waiting for agent.bravo.example.",
		"  parent sync:    held until the zone is caught up",
		"  DS set:         unknown, waiting for agent.bravo.example. (not spoken)")

	// held for the zone's SIG(0) key as well (step 7b): its own line
	report.KeyHold = "held until the zone's SIG(0) key is held and bootstrapped (poll running)"
	out, err = parentSyncCLI(t, agent(report))("status", "-z", zone)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines(t, "status, held for the key", out,
		"  parent sync:    held until the zone is caught up",
		"  parent sync:    held until the zone's SIG(0) key is held and bootstrapped (poll running)")

	// several KEYs at the apex: no zone key at all (step 7b)
	report.ApexPublished, report.ApexKeys = true, 2
	report.KeyHold = "held until the zone's SIG(0) key is held and bootstrapped (not held)"
	out, err = parentSyncCLI(t, agent(report))("status", "-z", zone)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines(t, "status, several KEYs", out,
		"  KEY at apex:    several (2); an operator has to leave one",
		"  parent sync:    held until the zone's SIG(0) key is held and bootstrapped (not held)")
}

// The zone's instructions, through the agent's real handler: `parentsync
// status` shows what the agent keeps, `zone instructions forget` clears a
// steady zone's serials, and is refused for a zone with an owner error.
func TestTheAgentShowsAndForgetsTheZonesSerials(t *testing.T) {
	const id, zone = "agent.alpha.example.", "instructions.parentsync.example."
	conf, hdb, _ := parentSyncTestConf(t, id, zone)
	if err := hdb.InitInstructionTables(); err != nil {
		t.Fatal(err)
	}
	store, err := tdnsmp.LoadInstructionStore(hdb)
	if err != nil {
		t.Fatal(err)
	}
	conf.InternalMp.Instructions = store
	agent := conf.APIagent(t.Context(), nil, hdb)
	status := parentSyncCLI(t, agent)
	forget := agentCLI(t, agent, "agent", "zone", "instructions", "forget")

	seven := &tdnsmp.Instructions{Serial: 7, HasParam: true, Servers: []string{"alpha", "bravo"}}
	store.Note(zone, seven, nil)
	out, err := status("status", "-z", zone)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines(t, "status", out, fmt.Sprintf("  instructions:   active 7 (%s), copy 7; not enforced", seven.Digest()))

	if out, err := forget("-z", zone); err != nil || !strings.Contains(out, "Forgot the stored serials of zone "+zone) {
		t.Fatalf("forget: %v, %q", err, out)
	}
	if out, _ := status("status", "-z", zone); !strings.Contains(out, "  instructions:   none kept\n") {
		t.Errorf("status after forget:\n%s", out)
	}

	store.Note(zone, seven, nil)
	store.Note(zone, &tdnsmp.Instructions{Serial: 7, HasParam: true, Servers: []string{"alpha"}}, nil)
	if out, err := forget("-z", zone); err == nil || !strings.Contains(err.Error(), "not steady") {
		t.Errorf("forget with an owner error: %v, %q; want refused", err, out)
	}
}

// The status prints what each member tells of the zone's instructions (plan
// S5a), this agent first, with the notes the rigs read: (lags), an owner
// error with its text, and the Hold column empty until S6.
func TestThePerMemberInstructionsArePrinted(t *testing.T) {
	heard := time.Date(2026, 10, 28, 15, 4, 2, 0, time.UTC)
	sd := func(serial uint32) *tdnsmp.SerialDigest { return &tdnsmp.SerialDigest{Serial: serial, Digest: "d"} }
	fortyTwo := uint32(42)
	var b bytes.Buffer
	printParentSyncStatus(&b, tdnsmp.ParentSyncStatus{Zone: "z.example.", InstructionMembers: []tdnsmp.MemberInstructions{
		{Identity: "agent.alpha.example.", Self: true, Active: sd(41), Newest: sd(42), Crypto: true},
		{Identity: "agent.bravo.example.", Active: sd(41), Newest: sd(41), Rollover: true, Lags: true, Crypto: true, Heard: heard,
			Error: "serial 41 told with two digests (a, b)"},
		{Identity: "agent.delta.example.", Newest: sd(43), Alone: true, OtherDigest: &fortyTwo, Heard: heard},
	}})
	out := b.String()
	wantLines(t, "status", out,
		"Instructions, per member:",
		"  Active  Newest  Rollover  Hold  Heard     Identity",
		"  41      42      no        -     -         agent.alpha.example. (this agent)",
		"  41      41      yes       -     15:04:02  agent.bravo.example. (lags) (owner error: serial 41 told with two digests (a, b))",
		"  -       43      no        -     15:04:02  agent.delta.example. (tells 43, which no other member holds) (another digest at 42) (payload encryption off)")
	wantNoControls(t, "status", out)
}
