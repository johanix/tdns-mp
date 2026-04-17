/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * API handler for MP signer management commands.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func (conf *Config) APImpSigner() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var req CombinerDebugPost
		err := decoder.Decode(&req)
		if err != nil {
			lgApi.Warn("error decoding request", "handler", "mpSigner", "err", err)
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /signer request", "cmd", req.Command, "from", r.RemoteAddr)

		resp := CombinerDebugResponse{
			Time: time.Now(),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "mpSigner", "err", err)
			}
		}()

		switch req.Command {
		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown signer command: %s", req.Command)
		}
	}
}
