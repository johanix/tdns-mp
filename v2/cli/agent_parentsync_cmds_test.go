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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	tdnsmp "github.com/johanix/tdns-mp/v2"
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
		root.SetArgs(append([]string{"agent", "parentsync"}, args...))
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

	return conf.APIagent(t.Context(), nil, hdb), sak.Keys[0].KeyId
}

func wantLines(t *testing.T, what, out string, lines ...string) {
	t.Helper()
	for _, want := range lines {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("%s lacks the line %q:\n%s", what, want, out)
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
	for _, r := range out {
		if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			t.Errorf("status printed control character %U:\n%q", r, out)
		}
	}

	// A lease that has run out is no leader, whoever held it.
	report.LeaderExpiry = checked.Add(-3 * time.Minute)
	out, err = parentSyncCLI(t, agent(report))("status", "-z", zone)
	if err != nil {
		t.Fatalf("status with an expired lease: %v", err)
	}
	wantLines(t, "status with an expired lease", out,
		"  leader:         none (the lease of agent.bravo.example. has expired)")
}
