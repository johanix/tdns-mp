/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"encoding/json"
	"net/http"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
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

		for item := range tdns.Zones.IterBuffered() {
			zname := item.Key
			zd := item.Val
			if !zd.Options[tdns.OptMultiProvider] {
				continue
			}

			info := MPZoneInfo{}

			// Collect options from both zd.Options and zd.MP.MPdata.Options
			seen := make(map[tdns.ZoneOption]bool)
			for opt, val := range zd.Options {
				if val {
					info.Options = append(info.Options, opt)
					seen[opt] = true
				}
			}
			if zd.MP != nil && zd.MP.MPdata != nil {
				for opt, val := range zd.MP.MPdata.Options {
					if val && !seen[opt] {
						info.Options = append(info.Options, opt)
					}
				}
			}

			// Extract HSYNCPARAM data from zone apex
			apex, err := zd.GetOwner(zd.ZoneName)
			if err == nil && apex != nil {
				hsyncparamRRset, exists := apex.RRtypes.Get(core.TypeHSYNCPARAM)
				if exists && len(hsyncparamRRset.RRs) > 0 {
					if prr, ok := hsyncparamRRset.RRs[0].(*dns.PrivateRR); ok {
						if hp, ok := prr.Data.(*core.HSYNCPARAM); ok {
							switch hp.GetNSmgmt() {
							case core.HsyncNSmgmtAGENT:
								info.NSmgmt = "agent"
							default:
								info.NSmgmt = "owner"
							}
							switch hp.GetParentSync() {
							case core.HsyncParentSyncAgent:
								info.ParentSync = "agent"
							default:
								info.ParentSync = "owner"
							}
							info.Servers = hp.GetServers()
							info.Signers = hp.GetSigners()
							info.Auditors = hp.GetAuditors()
							info.Suffix = hp.GetSuffix()
						}
					}
				}
			}

			if info.NSmgmt == "" {
				info.NSmgmt = "owner"
			}
			if info.ParentSync == "" {
				info.ParentSync = "owner"
			}
			if info.Servers == nil {
				info.Servers = []string{}
			}
			if info.Signers == nil {
				info.Signers = []string{}
			}
			if info.Auditors == nil {
				info.Auditors = []string{}
			}

			resp.MPZones[zname] = info
		}
	}
}
