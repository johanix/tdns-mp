/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// APIimr handles the /imr management API endpoint for tdns-mpagent
// (and any other tdns-mp app that hosts an in-process IMR). It mirrors
// tdns.APIimr but lives here so the handler can use tdns-mp's own
// AgentMgmtPost / AgentMgmtResponse types and the Imr wrapper.
//
// MP-specific commands continue to be served by APIagent at /agent.
// Keeping the IMR commands on a separate /imr endpoint means tdns-mp
// can host both without URL collisions with tdns's /imr (one lives in
// the tdns library, the other in the tdns-mp library, but a process
// embedding both libraries would otherwise see overlap).
func (conf *Config) APIimr() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var amp AgentMgmtPost
		err := decoder.Decode(&amp)
		if err != nil {
			lgApi.Warn("error decoding imr command post", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /imr request", "cmd", amp.Command, "from", r.RemoteAddr)

		resp := AgentMgmtResponse{
			Time:     time.Now(),
			Identity: AgentId(conf.Config.MultiProvider.Identity),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := tdns.SanitizeForJSON(resp)
			if err := json.NewEncoder(w).Encode(sanitizedResp); err != nil {
				lgApi.Error("json encoder failed", "err", err)
			}
		}()

		switch amp.Command {
		case "imr-query":
			imr := &Imr{tdns.Globals.ImrEngine}
			if imr.Imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			qname, _ := amp.Data["qname"].(string)
			qtypeStr, _ := amp.Data["qtype"].(string)
			if qname == "" || qtypeStr == "" {
				resp.Error = true
				resp.ErrorMsg = "qname and qtype are required"
				return
			}
			qname = dns.Fqdn(qname)
			qtype, ok := dns.StringToType[strings.ToUpper(qtypeStr)]
			if !ok {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("unknown RR type: %s", qtypeStr)
				return
			}
			crrset := imr.Cache.Get(qname, qtype)
			if crrset == nil {
				resp.Msg = fmt.Sprintf("No cache entry for %s %s", qname, qtypeStr)
				return
			}
			entry := map[string]any{
				"name":       crrset.Name,
				"rrtype":     dns.TypeToString[crrset.RRtype],
				"rcode":      dns.RcodeToString[int(crrset.Rcode)],
				"ttl":        crrset.Ttl,
				"expiration": crrset.Expiration.Format(time.RFC3339),
				"expires_in": time.Until(crrset.Expiration).Truncate(time.Second).String(),
				"context":    fmt.Sprintf("%d", crrset.Context),
				"state":      fmt.Sprintf("%d", crrset.State),
			}
			if crrset.RRset != nil {
				var rrs []string
				for _, rr := range crrset.RRset.RRs {
					rrs = append(rrs, rr.String())
				}
				entry["records"] = rrs
			}
			resp.Data = entry
			resp.Msg = fmt.Sprintf("Cache entry for %s %s", qname, dns.TypeToString[qtype])

		case "imr-flush":
			imr := &Imr{tdns.Globals.ImrEngine}
			if imr.Imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			qname, _ := amp.Data["qname"].(string)
			if qname == "" {
				resp.Error = true
				resp.ErrorMsg = "qname is required"
				return
			}
			qname = dns.Fqdn(qname)
			removed, err := imr.Cache.FlushDomain(qname, false)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("flush failed: %v", err)
				return
			}
			resp.Msg = fmt.Sprintf("Flushed %d cache entries at and below %s", removed, qname)

		case "imr-reset":
			imr := &Imr{tdns.Globals.ImrEngine}
			if imr.Imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			removed := imr.Cache.FlushAll()
			resp.Msg = fmt.Sprintf("IMR cache reset: flushed %d entries (root NS and glue preserved)", removed)

		case "imr-show":
			imr := &Imr{tdns.Globals.ImrEngine}
			if imr.Imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			identity := string(amp.AgentId)
			if identity == "" {
				resp.Error = true
				resp.ErrorMsg = "agent_id (--id) is required"
				return
			}
			identity = dns.Fqdn(identity)
			var entries []map[string]any
			idCanon := strings.ToLower(identity)
			for item := range imr.Cache.RRsets.IterBuffered() {
				cr := item.Val
				name := strings.ToLower(cr.Name)
				if name != idCanon && !strings.HasSuffix(name, "."+idCanon) {
					continue
				}
				entry := map[string]any{
					"name":       cr.Name,
					"rrtype":     dns.TypeToString[cr.RRtype],
					"rcode":      dns.RcodeToString[int(cr.Rcode)],
					"ttl":        cr.Ttl,
					"expiration": cr.Expiration.Format(time.RFC3339),
					"expires_in": time.Until(cr.Expiration).Truncate(time.Second).String(),
				}
				if cr.RRset != nil {
					var rrs []string
					for _, rr := range cr.RRset.RRs {
						rrs = append(rrs, rr.String())
					}
					entry["records"] = rrs
				}
				entries = append(entries, entry)
			}
			resp.Data = entries
			resp.Msg = fmt.Sprintf("Found %d cache entries for identity %s", len(entries), identity)

		case "imr-dump-tuning":
			t := conf.Config.Imr.Tuning
			p := cache.GetBackoffPolicy()
			upgradeStr := "true (legacy default)"
			if t.UpgradeIndirectCacheHits != nil {
				if *t.UpgradeIndirectCacheHits {
					upgradeStr = "true (explicit)"
				} else {
					upgradeStr = "false (explicit)"
				}
			}
			resp.Data = map[string]any{
				"backoff": map[string]any{
					"first_failure":   p.FirstFailure.String(),
					"max_failure":     p.MaxFailure.String(),
					"multiplier":      p.Multiplier,
					"jitter_fraction": p.JitterFraction,
					"routing_failure": p.RoutingFailure.String(),
					"lame_delegation": p.LameDelegation.String(),
				},
				"address_family": map[string]any{
					"window_duration":   t.AddressFamily.WindowDuration.String(),
					"failure_threshold": t.AddressFamily.FailureThreshold,
					"suspect_duration":  t.AddressFamily.SuspectDuration.String(),
					"probe_interval":    t.AddressFamily.ProbeInterval.String(),
				},
				"discovery": map[string]any{
					"retry_after_failure": t.Discovery.RetryAfterFailure.String(),
					"max_failures":        t.Discovery.MaxFailures,
				},
				"query_budget":                t.QueryBudget.String(),
				"upgrade_indirect_cache_hits": upgradeStr,
			}
			resp.Msg = "IMR tuning snapshot"

		case "imr-dump-zone-backoffs":
			imr := &Imr{tdns.Globals.ImrEngine}
			if imr.Imr == nil || imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			zoneFilter, _ := amp.Data["zone"].(string)
			if zoneFilter != "" {
				zoneFilter = dns.Fqdn(zoneFilter)
			}
			now := time.Now()
			type zoneRecord struct {
				Zone      string `json:"zone"`
				Address   string `json:"address"`
				Transport string `json:"transport"`
				NextTry   string `json:"next_try"`
				Remain    string `json:"remaining"`
				Count     uint8  `json:"failure_count"`
				Err       string `json:"last_error,omitempty"`
			}
			var records []zoneRecord
			for item := range imr.Cache.ZoneMap.IterBuffered() {
				if zoneFilter != "" && item.Key != zoneFilter {
					continue
				}
				snap := item.Val.SnapshotAddressBackoffs(now)
				for key, b := range snap {
					rem := b.NextTry.Sub(now)
					if rem < 0 {
						rem = 0
					}
					records = append(records, zoneRecord{
						Zone: item.Key, Address: key.Addr,
						Transport: core.TransportToString[key.Transport],
						NextTry:   b.NextTry.Format(time.RFC3339),
						Remain:    rem.Truncate(time.Second).String(),
						Count:     b.FailureCount, Err: b.LastError,
					})
				}
			}
			resp.Data = records
			if len(records) == 0 {
				if zoneFilter != "" {
					resp.Msg = fmt.Sprintf("No zone-scoped backoffs for %s", zoneFilter)
				} else {
					resp.Msg = "No zone-scoped backoffs recorded"
				}
			} else {
				resp.Msg = fmt.Sprintf("%d zone-scoped backoffs", len(records))
			}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown IMR command: %s", amp.Command)
			resp.Error = true
		}
	}
}
