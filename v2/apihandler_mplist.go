/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"encoding/json"
	"net/http"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// APImplist handles /zone/mplist requests. It iterates all zones with
// OptMultiProvider and returns their HSYNCPARAM details.
func (conf *Config) APImplist() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		lgApi.Debug("received /zone/mplist request", "from", r.RemoteAddr)

		resp := MPListResponse{
			Time:    time.Now(),
			MPZones: map[string]MPZoneInfo{},
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("json encode failed", "handler", "mplist", "err", err)
			}
		}()

		for item := range Zones.IterBuffered() {
			zname := item.Key
			zd := item.Val
			if !zd.Options[tdns.OptMultiProvider] {
				continue
			}

			resp.MPZones[zname] = MPZoneInfoFromMPZoneData(zd)
		}
	}
}
