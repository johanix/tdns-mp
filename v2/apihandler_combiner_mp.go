/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * API handler for MP combiner management commands.
 * Registered on /combiner/mp — independent of the legacy tdns combiner endpoints.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

func (conf *Config) APImpCombiner() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req tdns.CombinerDebugPost
		err := decoder.Decode(&req)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "mpCombiner", "err", err)
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /combiner/mp request", "cmd", req.Command, "from", r.RemoteAddr)

		resp := tdns.CombinerDebugResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "mpCombiner", "err", err)
			}
		}()

		switch req.Command {
		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown combiner/mp command: %s", req.Command)
		}
	}
}
