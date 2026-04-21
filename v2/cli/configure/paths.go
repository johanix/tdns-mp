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
	pathMpcli      = configDir + "/tdns-mpcli.yaml"
)

// allConfigPaths returns the four config file paths in a
// stable order (agent, signer, combiner, mpcli). Iteration order
// matters for deterministic diff output.
func allConfigPaths() []string {
	return []string{pathMpagent, pathMpsigner, pathMpcombiner, pathMpcli}
}
