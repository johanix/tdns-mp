/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * /combiner/config — combiner-side runtime config introspection.
 * Mirrors the agent's /agent (command "config") endpoint, but for
 * the combiner role. Operators use this via "tdns-mpcli combiner
 * config status [-v]" to confirm the running combiner's effective
 * multi-provider config without inspecting on-disk YAML.
 *
 * Secrets are not exposed. Only structural fields (identity, role,
 * options, agent identities, etc.) are returned.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"
)

// APIcombinerConfig handles /combiner/config requests.
func (conf *Config) APIcombinerConfig() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req CombinerConfigPost
		if err := decoder.Decode(&req); err != nil {
			lgApi.Warn("error decoding request", "handler", "combinerConfig", "err", err)
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /combiner/config request", "cmd", req.Command, "from", r.RemoteAddr)

		resp := CombinerConfigResponse{Time: time.Now()}
		defer func() {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				lgApi.Error("json encode failed", "handler", "combinerConfig", "err", err)
			}
		}()

		mp := conf.MpConfig()
		if mp == nil {
			resp.Error = true
			resp.ErrorMsg = "no multi-provider config loaded"
			return
		}

		switch req.Command {
		case "status":
			resp.Identity = mp.Identity
			resp.Role = mp.Role
			resp.Active = mp.Active
			resp.CombinerOptions = combinerOptionsAsStrings(mp.CombinerOptions)
			resp.ChunkMode = mp.ChunkMode
			resp.ChunkMaxSize = mp.ChunkMaxSize
			resp.AgentCount = len(mp.Agents)

			if req.Verbose {
				for _, a := range mp.Agents {
					if a == nil {
						continue
					}
					resp.AgentIdentities = append(resp.AgentIdentities, a.Identity)
				}
				resp.ProtectedNamespaces = append([]string(nil), mp.ProtectedNamespaces...)
				resp.SyncApiListen = append([]string(nil), mp.SyncApi.Addresses.Listen...)
				for _, pz := range mp.ProviderZones {
					resp.ProviderZones = append(resp.ProviderZones, pz.Zone)
				}
			}

			resp.Msg = fmt.Sprintf("combiner %q config status", mp.Identity)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("unknown command: %q", req.Command)
		}
	}
}

// combinerOptionsAsStrings flattens the typed CombinerOptions map
// into a sorted slice of canonical string names, suitable for JSON.
func combinerOptionsAsStrings(opts map[CombinerOption]bool) []string {
	if len(opts) == 0 {
		return nil
	}
	out := make([]string, 0, len(opts))
	for opt, enabled := range opts {
		if !enabled {
			continue
		}
		if name, ok := CombinerOptionToString[opt]; ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
