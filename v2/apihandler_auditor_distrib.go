/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor distrib endpoint. Mirrors the agent's role-independent
 * commands (peer-list, peer-zones, zone-agents); the auditor has
 * no distribution cache and so does not implement the agent's
 * cache-only commands (list, purge, op).
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

func (conf *Config) APIauditorDistrib() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req AgentDistribPost
		if err := decoder.Decode(&req); err != nil {
			lgApi.Warn("error decoding request", "handler", "auditorDistrib", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /auditor/distrib request", "cmd", req.Command, "from", r.RemoteAddr)

		resp := AgentDistribResponse{Time: time.Now()}
		handledManually := false
		defer func() {
			if !handledManually {
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(tdns.SanitizeForJSON(resp)); err != nil {
					lgApi.Error("json encode failed", "handler", "auditorDistrib", "err", err)
				}
			}
		}()

		handled, writeHandled, msg, data, errMsg, agents := handleSharedDistribCommand(conf, w, req.Command, req.Zone, resp.Time)
		if !handled {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("unknown auditor distrib command: %q", req.Command)
			return
		}
		if writeHandled {
			handledManually = true
			return
		}
		if errMsg != "" {
			resp.Error = true
			resp.ErrorMsg = errMsg
			return
		}
		resp.Msg = msg
		if data != nil {
			resp.Data = data
		}
		if agents != nil {
			resp.Agents = agents
		}
	}
}
