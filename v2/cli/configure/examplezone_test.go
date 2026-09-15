package configure

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An existing example zone file is left alone; the warning must follow
// the HSYNC3 records it parses to, not text anywhere in the file.
func TestEnsureExampleZoneChecksHsync3Identities(t *testing.T) {
	const soa = "$TTL 300\nmptest.example. IN SOA ns1.mptest.example. hostmaster.mptest.example. 1 3600 600 604800 300\n"
	for _, tc := range []struct {
		name    string
		records string
		warning bool
	}{
		{"HSYNC3 names the agent", "mptest.example. IN HSYNC3 ON alpha agent.alpha.example. .\n", false},
		{"HSYNC3 names it in other case", "mptest.example. IN HSYNC3 ON alpha Agent.Alpha.Example. .\n", false},
		{"only a comment names it", "; agent.alpha.example.\nmptest.example. IN HSYNC3 ON bravo agent.bravo.example. .\n", true},
		{"a longer identity contains it", "mptest.example. IN HSYNC3 ON alpha xagent.alpha.example. .\n", true},
		{"the file does not parse", "mptest.example. IN HSYNC3 ON\n", true},
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
			cv := CoordinatedValues{Agent: AgentValues{Identity: "agent.alpha.example."}}
			var out bytes.Buffer
			gen, err := ensureExampleZone(cv, l, &out)
			if err != nil || gen {
				t.Fatalf("ensureExampleZone: generated=%v err=%v", gen, err)
			}
			if got := strings.Contains(out.String(), "WARNING"); got != tc.warning {
				t.Errorf("warning=%v, want %v; output %q", got, tc.warning, out.String())
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
