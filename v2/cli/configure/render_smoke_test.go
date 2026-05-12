package configure

import (
	"strings"
	"testing"
)

func TestRenderAllSmoke(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cv      CoordinatedValues
		paths   []string
		without []string
	}{
		{
			name: "without auditor",
			cv: CoordinatedValues{
				Global: GlobalValues{
					KeysDir:    "/etc/tdns/keys",
					CertsDir:   "/etc/tdns/certs",
					PublicIP:   "203.0.113.5",
					InternalIP: "10.0.0.5",
				},
				Agent:    AgentValues{Identity: "agent.test.", ApiKey: "key-a"},
				Signer:   SignerValues{Identity: "signer.test.", ApiKey: "key-s"},
				Combiner: CombinerValues{Identity: "combiner.test.", ApiKey: "key-c"},
			},
			paths:   []string{pathMpagent, pathMpsigner, pathMpcombiner, pathMpcli},
			without: []string{pathMpauditor},
		},
		{
			name: "with auditor",
			cv: CoordinatedValues{
				Global: GlobalValues{
					KeysDir:    "/etc/tdns/keys",
					CertsDir:   "/etc/tdns/certs",
					PublicIP:   "203.0.113.5",
					InternalIP: "10.0.0.5",
				},
				Agent:    AgentValues{Identity: "agent.test.", ApiKey: "key-a"},
				Signer:   SignerValues{Identity: "signer.test.", ApiKey: "key-s"},
				Combiner: CombinerValues{Identity: "combiner.test.", ApiKey: "key-c"},
				Auditor:  AuditorValues{Identity: "auditor.test.", ApiKey: "key-au"},
			},
			paths: []string{pathMpagent, pathMpsigner, pathMpcombiner, pathMpauditor, pathMpcli},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderAll(tc.cv)
			if err != nil {
				t.Fatalf("renderAll: %v", err)
			}
			for _, p := range tc.paths {
				body, ok := out[p]
				if !ok {
					t.Errorf("missing %q in render output", p)
					continue
				}
				if len(body) == 0 {
					t.Errorf("empty render for %q", p)
				}
			}
			for _, p := range tc.without {
				if _, ok := out[p]; ok {
					t.Errorf("expected %q to be absent (auditor off)", p)
				}
			}
			// Spot-check that mpcli output includes the auditor block
			// only when AuditorValues.Identity is set.
			mpcli := out[pathMpcli]
			if tc.cv.Auditor.Identity == "" && strings.Contains(mpcli, "tdns-mpauditor") {
				t.Errorf("mpcli includes tdns-mpauditor entry when auditor disabled")
			}
			if tc.cv.Auditor.Identity != "" && !strings.Contains(mpcli, "tdns-mpauditor") {
				t.Errorf("mpcli missing tdns-mpauditor entry when auditor enabled")
			}
		})
	}
}
