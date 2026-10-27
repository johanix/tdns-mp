package configure

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An existing example zone file is left alone; the warning must follow
// the HSYNC3 records it parses to, not text anywhere in the file, and
// must name what is missing.
func TestEnsureExampleZoneChecksHsync3Identities(t *testing.T) {
	const soa = "$TTL 300\nmptest.example. IN SOA ns1.mptest.example. hostmaster.mptest.example. 1 3600 600 604800 300\n"
	const agentRR = "mptest.example. IN HSYNC3 ON alpha agent.alpha.example. .\n"
	for _, tc := range []struct {
		name    string
		records string
		auditor string
		want    []string // substrings of the output; none means no warning
	}{
		{"HSYNC3 names the agent", agentRR, "", nil},
		{"HSYNC3 names it in other case", "mptest.example. IN HSYNC3 ON alpha Agent.Alpha.Example. .\n", "", nil},
		{"only a comment names it", "; agent.alpha.example.\nmptest.example. IN HSYNC3 ON bravo agent.bravo.example. .\n", "",
			[]string{"has no HSYNC3 record for agent.alpha.example."}},
		{"a longer identity contains it", "mptest.example. IN HSYNC3 ON alpha xagent.alpha.example. .\n", "",
			[]string{"has no HSYNC3 record for agent.alpha.example."}},
		{"HSYNC3 names agent and auditor", agentRR + "mptest.example. IN HSYNC3 ON auditor auditor.alpha.example. .\n",
			"auditor.alpha.example.", nil},
		{"only a comment names the auditor", agentRR + "; auditor.alpha.example.\n", "auditor.alpha.example.",
			[]string{"has no HSYNC3 record for auditor.alpha.example."}},
		{"the file does not parse", "mptest.example. IN HSYNC3 ON\n", "",
			[]string{"does not parse as a zone file"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := testLayout(t.TempDir())
			path := l.exampleZoneFile()
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			content := soa + tc.records
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			cv := CoordinatedValues{
				Agent:   AgentValues{Identity: "agent.alpha.example."},
				Auditor: AuditorValues{Identity: tc.auditor},
			}
			var out bytes.Buffer
			gen, err := ensureExampleZone(cv, l, &out)
			if err != nil || gen {
				t.Fatalf("ensureExampleZone: generated=%v err=%v", gen, err)
			}
			got := out.String()
			if len(tc.want) == 0 && strings.Contains(got, "WARNING") {
				t.Errorf("unexpected warning: %q", got)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("output %q lacks %q", got, w)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != content {
				t.Errorf("existing zone file was modified")
			}
		})
	}
}

// The provider's label is a Label, or the example zone would not load: tdns
// refuses any other label in HSYNC3 and HSYNCPARAM. An agent identity that
// gives another label is refused, and no file is written.
func TestTheExampleZoneRefusesAProviderLabelThatIsNotALabel(t *testing.T) {
	for _, tc := range []struct {
		identity string
		label    string // "" when refused
	}{
		{"agent.alpha.example.", "alpha"},
		{"Agent.ALPHA.example.", "alpha"},
		{"ns-1.example.", "ns-1"},
		{"agent.averyveryverylongname.example.", ""},
		{"agent.under_score.example.", ""},
	} {
		t.Run(tc.identity, func(t *testing.T) {
			l := testLayout(t.TempDir())
			cv := CoordinatedValues{Agent: AgentValues{Identity: tc.identity}}
			gen, err := ensureExampleZone(cv, l, io.Discard)
			if tc.label == "" {
				if err == nil || gen || !strings.Contains(err.Error(), "not a Label") {
					t.Fatalf("generated=%v err=%v; want refused", gen, err)
				}
				if _, statErr := os.Stat(l.exampleZoneFile()); !os.IsNotExist(statErr) {
					t.Errorf("a refused identity left a zone file: %v", statErr)
				}
				return
			}
			if err != nil || !gen {
				t.Fatalf("generated=%v err=%v", gen, err)
			}
			if got := providerLabel(tc.identity); got != tc.label {
				t.Errorf("label %q, want %q", got, tc.label)
			}
		})
	}
}

// The label is checked when the configs are rendered, before the preview
// and before any key or certificate is made, and only when the example zone
// will be written: an operator's own zone file is left to the operator.
func TestABadProviderLabelIsRefusedBeforeAnyKeyIsMade(t *testing.T) {
	root := t.TempDir()
	l := testLayout(root)
	cv := testValues(root, "10.0.0.1", "192.0.2.1", false)
	cv.Agent.Identity = "agent.under_score.example."
	if _, err := renderAllIn(cv, l); err == nil || !strings.Contains(err.Error(), "not a Label") {
		t.Fatalf("rendering with no example zone: %v; want refused", err)
	}
	if err := os.MkdirAll(filepath.Dir(l.exampleZoneFile()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.exampleZoneFile(), []byte("; the operator's own\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := renderAllIn(cv, l); err != nil {
		t.Errorf("rendering with the operator's zone file: %v", err)
	}
}
