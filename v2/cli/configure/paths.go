/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * mpcli configure subpackage: filesystem layout.
 */
package configure

import "path/filepath"

// fsLayout says where the generated files go and which paths the
// generated configs name. `configure` always uses defaultLayout; tests
// render into a temporary tree.
type fsLayout struct {
	ConfigDir  string // daemon and CLI configs
	ZoneDir    string // the example zone's zone file
	DbDir      string // daemon databases
	LogDir     string // daemon and CLI logs
	LibexecDir string // daemon binaries, named by mpcli's command: entries
}

var defaultLayout = fsLayout{
	ConfigDir:  "/etc/tdns",
	ZoneDir:    "/etc/tdns/zones",
	DbDir:      "/var/lib/tdns",
	LogDir:     "/var/log/tdns",
	LibexecDir: "/usr/local/libexec",
}

func (l fsLayout) configFile(name string) string { return filepath.Join(l.ConfigDir, name) }

func (l fsLayout) mpagent() string    { return l.configFile("tdns-mpagent.yaml") }
func (l fsLayout) mpsigner() string   { return l.configFile("tdns-mpsigner.yaml") }
func (l fsLayout) mpcombiner() string { return l.configFile("tdns-mpcombiner.yaml") }
func (l fsLayout) mpauditor() string  { return l.configFile("tdns-mpauditor.yaml") }
func (l fsLayout) mpcli() string      { return l.configFile("tdns-mpcli.yaml") }

// exampleZoneFile is the zone file the combiner loads the example zone from.
func (l fsLayout) exampleZoneFile() string {
	return filepath.Join(l.ZoneDir, exampleZone+"zone")
}

var (
	pathMpagent    = defaultLayout.mpagent()
	pathMpsigner   = defaultLayout.mpsigner()
	pathMpcombiner = defaultLayout.mpcombiner()
	pathMpauditor  = defaultLayout.mpauditor()
	pathMpcli      = defaultLayout.mpcli()
)

// allConfigPaths returns the config file paths in a stable order
// (agent, signer, combiner, auditor, mpcli). Iteration order
// matters for deterministic diff output. The auditor file is
// always listed; whether content is rendered for it depends on
// whether the operator opted in (AuditorValues.Identity != "").
func allConfigPaths() []string {
	return []string{pathMpagent, pathMpsigner, pathMpcombiner, pathMpauditor, pathMpcli}
}
