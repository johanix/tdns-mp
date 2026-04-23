/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Role → clientKey registrations for tdns-mp daemons. Registered in
 * init() so any binary that imports this package (mpcli, in practice)
 * picks up the mp-specific daemon mappings — and the "agent" override
 * so mpcli talks to tdns-mpagent, not tdns-agent.
 */
package cli

import tdnscli "github.com/johanix/tdns/v2/cli"

func init() {
	tdnscli.RegisterRole("signer", "tdns-mpsigner")
	tdnscli.RegisterRole("combiner", "tdns-mpcombiner")
	tdnscli.RegisterRole("agent", "tdns-mpagent") // overrides the tdns default
}
