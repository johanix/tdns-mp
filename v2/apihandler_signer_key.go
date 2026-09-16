/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * /signer/key: the key lifecycle of an owned zone as tdns-mp runs it
 * (design §5, the replacement commands).
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type SignerKeyPost struct {
	Command string `json:"command"`
	Zone    string `json:"zone,omitempty"`
	Role    string `json:"role,omitempty"`
	KeyId   uint16 `json:"keyid,omitempty"`
	Policy  string `json:"policy,omitempty"`
}

type SignerKeyResponse struct {
	Time     time.Time           `json:"time"`
	Error    bool                `json:"error"`
	ErrorMsg string              `json:"error_msg,omitempty"`
	Msg      string              `json:"msg,omitempty"`
	Zones    []string            `json:"zones,omitempty"`
	Status   *KeyLifecycleStatus `json:"status,omitempty"`
}

// APIsignerKey serves the replacement commands: zones, status, rollover,
// rollover-cancel, retry, withdraw, policy-set.
func (conf *Config) APIsignerKey() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SignerKeyPost
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			lgApi.Warn("error decoding request", "handler", "signerKey", "err", err)
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}
		lgApi.Debug("received /signer/key request", "cmd", req.Command, "zone", req.Zone, "from", r.RemoteAddr)
		resp := SignerKeyResponse{Time: time.Now()}
		defer func() {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				lgApi.Error("json encode failed", "handler", "signerKey", "err", err)
			}
		}()
		e := conf.InternalMp.KeyLifecycle
		if e == nil {
			resp.Error, resp.ErrorMsg = true, "tdns-mp's key lifecycle engine is not running"
			return
		}
		var err error
		switch req.Command {
		case "zones":
			resp.Zones = e.Zones()
		case "status", "policy":
			resp.Status, err = e.Status(req.Zone)
		case "rollover":
			resp.Msg, err = e.RequestRollover(req.Zone, req.Role)
		case "rollover-cancel":
			resp.Msg, err = e.CancelRollover(req.Zone, req.Role)
		case "retry":
			resp.Msg, err = e.Retry(req.Zone, req.KeyId)
		case "withdraw":
			resp.Msg, err = e.Withdraw(req.Zone, req.KeyId)
		case "policy-set":
			resp.Msg, err = e.SetPolicy(r.Context(), req.Zone, req.Policy)
		default:
			err = fmt.Errorf("unknown signer key command: %q", req.Command)
		}
		if err != nil {
			resp.Error, resp.ErrorMsg = true, err.Error()
		}
	}
}
