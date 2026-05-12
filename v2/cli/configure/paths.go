/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * mpcli configure subpackage: fixed filesystem paths.
 */
package configure

const (
	configDir = "/etc/tdns"

	pathMpagent    = configDir + "/tdns-mpagent.yaml"
	pathMpsigner   = configDir + "/tdns-mpsigner.yaml"
	pathMpcombiner = configDir + "/tdns-mpcombiner.yaml"
	pathMpauditor  = configDir + "/tdns-mpauditor.yaml"
	pathMpcli      = configDir + "/tdns-mpcli.yaml"
)

// allConfigPaths returns the config file paths in a stable order
// (agent, signer, combiner, auditor, mpcli). Iteration order
// matters for deterministic diff output. The auditor file is
// always listed; whether content is rendered for it depends on
// whether the operator opted in (AuditorValues.Identity != "").
func allConfigPaths() []string {
	return []string{pathMpagent, pathMpsigner, pathMpcombiner, pathMpauditor, pathMpcli}
}
