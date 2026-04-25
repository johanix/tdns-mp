/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

func (conf *Config) APIagent(refreshZoneCh chan<- tdns.ZoneRefresher, hdb *HsyncDB) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var amp AgentMgmtPost
		err := decoder.Decode(&amp)
		if err != nil {
			lgApi.Warn("error decoding agent command post", "err", err)
			http.Error(w, fmt.Sprintf("Invalid request format: %v", err), http.StatusBadRequest)
			return
		}

		lgApi.Debug("received /agent request", "cmd", amp.Command, "from", r.RemoteAddr)

		resp := AgentMgmtResponse{
			Time:     time.Now(),
			Identity: AgentId(conf.Config.MultiProvider.Identity),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := tdns.SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				lgApi.Error("json encoder failed", "err", err)
			}
		}()

		var zd *MPZoneData
		var exist bool
		noZoneCommands := map[string]bool{
			"config": true, "hsync-agentstatus": true,
			"discover": true, "hsync-locate": true, "hsync-send-hello": true,
			"imr-query": true, "imr-flush": true, "imr-reset": true, "imr-show": true,
		}
		if !noZoneCommands[amp.Command] {
			amp.Zone = ZoneName(dns.Fqdn(string(amp.Zone)))
			zd, exist = Zones.Get(string(amp.Zone))
			if !exist {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Zone %s is unknown", amp.Zone)
				return
			}
		}

		rch := make(chan *AgentMgmtResponse, 1)

		switch amp.Command {
		case "config":
			tmp := tdns.SanitizeForJSON(conf.Config.MultiProvider)
			if p, ok := tmp.(*tdns.MultiProviderConf); ok && p != nil {
				resp.AgentConfig = *p
			}
			resp.AgentConfig.Api.CertData = ""
			resp.AgentConfig.Api.KeyData = ""

		case "update-local-zonedata":
			lgApi.Debug("update-local-zonedata", "addedRRs", amp.AddedRRs, "removedRRs", amp.RemovedRRs)

			conf.InternalMp.MsgQs.Command <- &AgentMgmtPostPlus{
				amp,
				rch,
			}
			select {
			case r := <-rch:
				resp = *r

			case <-time.After(10 * time.Second):
				lgApi.Warn("no response from CommandHandler after 10 seconds")
				resp.Error = true
				resp.ErrorMsg = "No response from CommandHandler after 10 seconds, state unknown"
			}

		case "add-rr", "del-rr":
			// Add or delete an RR: store locally + sync to peers + send to combiner
			if len(amp.RRs) == 0 {
				resp.Error = true
				resp.ErrorMsg = "at least one RR is required"
				return
			}
			// Per-RRtype submission policy: allow NS (if nsmgmt=agent),
			// KEY (if parentsync=agent), DNSKEY (signers only),
			// CDS/CSYNC (signers + parentsync=agent). canSubmit is the
			// agent-side gate; whether the local combiner applies vs
			// persists-but-ignores is a separate (combiner-side)
			// decision driven by canApply.
			if zd != nil && zd.MPOptions[tdns.OptMPDisallowEdits] {
				policy := zd.getEditPolicy()
				for _, rrStr := range amp.RRs {
					parsed, err := dns.NewRR(rrStr)
					if err != nil {
						continue // will be caught by the parse loop below
					}
					if !policy.canSubmit(parsed.Header().Rrtype) {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("zone %s: %s submissions not allowed (edit policy: signed=%v, signer=%v, nsmgmt=%d, parentsync=%d)",
							amp.Zone, dns.TypeToString[parsed.Header().Rrtype],
							policy.ZoneSigned, policy.WeAreSigner, policy.NSmgmt, policy.ParentSync)
						return
					}
				}
			}

			isAdd := amp.Command == "add-rr"
			apex := dns.Fqdn(string(amp.Zone))
			var parsedRRs []dns.RR
			for _, rrStr := range amp.RRs {
				rr, err := dns.NewRR(rrStr)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("failed to parse RR %q: %v", rrStr, err)
					return
				}
				if dns.Fqdn(rr.Header().Name) != apex {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("record owner %q is not the zone apex %q", rr.Header().Name, apex)
					return
				}
				if !AllowedLocalRRtypes[rr.Header().Rrtype] {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("RR type %s is not allowed", dns.TypeToString[rr.Header().Rrtype])
					return
				}
				if isAdd {
					rr.Header().Class = dns.ClassINET
				} else {
					rr.Header().Class = dns.ClassNONE
				}
				parsedRRs = append(parsedRRs, rr)
			}

			zu := &ZoneUpdate{
				Zone:    amp.Zone,
				AgentId: AgentId(conf.Config.MultiProvider.Identity),
				RRs:     parsedRRs,
				RRsets:  make(map[uint16]core.RRset),
			}

			// Build per-RRtype REPLACE operations with the full
			// post-mutation set for each affected RRtype.
			//
			// Rationale: per-RR add/delete operations let the agent's
			// view diverge silently from the combiner's view of what
			// this agent contributed. Example: an agent adds NS=foo,
			// then changes mind and adds NS=bar via a separate
			// transaction. The combiner accumulates {foo, bar}; if foo
			// was actually meant to be replaced, it never gets cleaned
			// up. With REPLACE-shaped operations, every contribution is
			// the agent's complete current intended set, and stale RRs
			// drop automatically. Empty REPLACE is the well-defined
			// case for "I have no contribution for this RRtype".
			//
			// The post-mutation full set per RRtype is computed from
			// the agent's own SDE entry (its current contribution) plus
			// the in-flight add/delete delta.
			selfID := AgentId(conf.Config.MultiProvider.Identity)
			zdr := conf.InternalMp.ZoneDataRepo
			currentByType := make(map[uint16][]dns.RR)
			if zdr != nil {
				if agentRepo, ok := zdr.Get(amp.Zone); ok {
					if ownerData, ok := agentRepo.Get(selfID); ok {
						for _, rrtype := range ownerData.RRtypes.Keys() {
							rrset, ok := ownerData.RRtypes.Get(rrtype)
							if !ok {
								continue
							}
							currentByType[rrtype] = append([]dns.RR{}, rrset.RRs...)
						}
					}
				}
			}

			affectedRRtypes := make(map[uint16]bool)
			for _, rr := range parsedRRs {
				affectedRRtypes[rr.Header().Rrtype] = true
				rrset, exists := zu.RRsets[rr.Header().Rrtype]
				if !exists {
					rrset = core.RRset{
						Name:   rr.Header().Name,
						Class:  rr.Header().Class,
						RRtype: rr.Header().Rrtype,
					}
				}
				rrset.RRs = append(rrset.RRs, rr)
				zu.RRsets[rr.Header().Rrtype] = rrset
			}

			rrIsDuplicate := func(a, b dns.RR) bool { return dns.IsDuplicate(a, b) }
			for rrtype := range affectedRRtypes {
				newSet := append([]dns.RR{}, currentByType[rrtype]...)
				for _, rr := range parsedRRs {
					if rr.Header().Rrtype != rrtype {
						continue
					}
					if isAdd {
						alreadyPresent := false
						for _, existing := range newSet {
							if rrIsDuplicate(existing, rr) {
								alreadyPresent = true
								break
							}
						}
						if !alreadyPresent {
							inet := dns.Copy(rr)
							inet.Header().Class = dns.ClassINET
							newSet = append(newSet, inet)
						}
					} else {
						filtered := newSet[:0]
						for _, existing := range newSet {
							inet := dns.Copy(rr)
							inet.Header().Class = dns.ClassINET
							if !rrIsDuplicate(existing, inet) {
								filtered = append(filtered, existing)
							}
						}
						newSet = filtered
					}
				}
				records := make([]string, 0, len(newSet))
				for _, rr := range newSet {
					inet := dns.Copy(rr)
					inet.Header().Class = dns.ClassINET
					records = append(records, inet.String())
				}
				zu.Operations = append(zu.Operations, core.RROperation{
					Operation: "replace",
					RRtype:    dns.TypeToString[rrtype],
					Records:   records,
				})
			}

			action := "Adding"
			if !isAdd {
				action = "Removing"
			}
			lgApi.Info("RR operation", "cmd", amp.Command, "action", action, "count", len(parsedRRs), "zone", amp.Zone)

			force := false
			if amp.Data != nil {
				if f, ok := amp.Data["force"].(bool); ok {
					force = f
				}
			}
			cresp := make(chan *AgentMsgResponse, 1)
			select {
			case conf.InternalMp.MsgQs.SynchedDataUpdate <- &SynchedDataUpdate{
				Zone:       amp.Zone,
				AgentId:    AgentId(conf.Config.MultiProvider.Identity),
				UpdateType: "local",
				Update:     zu,
				Force:      force,
				Response:   cresp,
			}:
				// enqueued successfully
			case <-r.Context().Done():
				resp.Error = true
				resp.ErrorMsg = "request cancelled"
				resp.Status = "fail"
				return
			case <-time.After(2 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "SynchedDataUpdate queue full, try again later"
				resp.Status = "fail"
				return
			}

			select {
			case r := <-cresp:
				if r.Error {
					resp.Error = true
					resp.ErrorMsg = r.ErrorMsg
					resp.Msg = fmt.Sprintf("%s RR(s) failed: %s", amp.Command, r.ErrorMsg)
					resp.Status = "fail"
				} else {
					resp.Msg = fmt.Sprintf("%s %d RR(s) for zone %q", action, len(parsedRRs), amp.Zone)
					if r.Msg != "" {
						resp.Msg += " - " + r.Msg
					}
					resp.Status = "ok"
				}
			case <-r.Context().Done():
				resp.Error = true
				resp.ErrorMsg = "request cancelled"
				resp.Status = "fail"
			case <-time.After(5 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for SynchedDataEngine response"
				resp.Status = "timeout"
			}

		case "hsync-agentstatus":
			// Get the apex owner object
			agent, err := conf.InternalMp.AgentRegistry.GetAgentInfo(amp.AgentId)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("error getting agent info: %v", err)
				return
			}
			resp.Agents = []*Agent{agent}
			resp.Msg = fmt.Sprintf("Data for remote agent %q", amp.AgentId)

		case "discover":
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "No agent identity specified"
				return
			}

			amp.AgentId = AgentId(dns.Fqdn(string(amp.AgentId)))

			// Check authorization before discovery (DNS-38)
			if conf.InternalMp.AgentRegistry.TransportManager != nil {
				authorized, reason := conf.InternalMp.AgentRegistry.MPTransport.IsPeerAuthorized(string(amp.AgentId), string(amp.Zone))
				if !authorized {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("agent %q is not authorized (not in agent.authorized_peers config or HSYNC): %s", amp.AgentId, reason)
					return
				}
			}

			// Trigger discovery (always starts fresh discovery)
			conf.InternalMp.AgentRegistry.DiscoverAgentAsync(amp.AgentId, amp.Zone, nil)
			resp.Msg = fmt.Sprintf("Discovery started for agent %s", amp.AgentId)

		case "hsync-locate":
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "No agent identity specified"
				return
			}

			amp.AgentId = AgentId(dns.Fqdn(string(amp.AgentId)))
			agent, err := conf.InternalMp.AgentRegistry.GetAgentInfo(amp.AgentId)
			if err != nil {
				// Start async lookup and return a message that lookup is in progress
				conf.InternalMp.AgentRegistry.DiscoverAgentAsync(amp.AgentId, "", nil)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent lookup in progress for %s", amp.AgentId)
				return
			}

			// If agent info is incomplete, start a new lookup
			if agent.State == AgentStateNeeded {
				conf.InternalMp.AgentRegistry.DiscoverAgentAsync(amp.AgentId, "", nil)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent information is incomplete for %s, lookup in progress", amp.AgentId)
				return
			}

			resp.Agents = []*Agent{agent}
			resp.Msg = fmt.Sprintf("Found existing agent %s", amp.AgentId)

		case "hsync-send-hello":
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "No agent identity specified"
				return
			}

			amp.AgentId = AgentId(dns.Fqdn(string(amp.AgentId)))

			agent, exists := conf.InternalMp.AgentRegistry.S.Get(amp.AgentId)
			if !exists || agent.State < AgentStateKnown {
				// Try discovery first
				conf.InternalMp.AgentRegistry.DiscoverAgentAsync(amp.AgentId, "", nil)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("agent %s not yet discovered; discovery started — retry after a few seconds", amp.AgentId)
				return
			}

			myIdentity := AgentId(conf.Config.MultiProvider.Identity)
			helloMsg := &AgentHelloPost{
				MessageType: AgentMsgHello,
				MyIdentity:  myIdentity,
			}

			ahr, err := agent.SendApiHello(helloMsg)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("HELLO to %s failed: %v", amp.AgentId, err)
				return
			}
			if ahr.Error {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("HELLO rejected by %s: %s", amp.AgentId, ahr.ErrorMsg)
				return
			}
			resp.Msg = fmt.Sprintf("HELLO to %s succeeded: %s (time: %s)", amp.AgentId, ahr.Msg, ahr.Time.Format(time.RFC3339))

		case "refresh-keys":
			zd.RequestAndWaitForKeyInventory(r.Context(), conf.InternalMp.MPTransport)
			if !zd.GetKeystateOK() {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("KEYSTATE exchange failed for zone %s: %s", amp.Zone, zd.GetKeystateError())
			} else {
				inv := zd.GetLastKeyInventory()
				if inv == nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("KEYSTATE exchange returned no inventory for zone %s", amp.Zone)
					return
				}
				nForeign := 0
				for _, entry := range inv.Inventory {
					if entry.State == DnskeyStateForeign {
						nForeign++
					}
				}
				// Derive local DNSKEYs from KEYSTATE and feed changes into SDE
				changed, dskeyStatus, err := zd.LocalDnskeysFromKeystate()
				if err != nil {
					lgApi.Error("LocalDnskeysFromKeystate failed", "err", err)
				}
				if changed && dskeyStatus != nil {
					select {
					case zd.SyncQ <- SyncRequest{
						Command:      "SYNC-DNSKEY-RRSET",
						ZoneName:     ZoneName(zd.ZoneName),
						ZoneData:     zd.ZoneData,
						DnskeyStatus: dskeyStatus,
					}:
					case <-r.Context().Done():
						resp.Error = true
						resp.ErrorMsg = "request cancelled while enqueuing SYNC-DNSKEY-RRSET"
						return
					case <-time.After(2 * time.Second):
						resp.Error = true
						resp.ErrorMsg = "SyncQ full, SYNC-DNSKEY-RRSET not enqueued"
						return
					}
				}
				resp.Msg = fmt.Sprintf("Key inventory refreshed for zone %s: %d keys (%d local, %d foreign)",
					amp.Zone, len(inv.Inventory),
					len(inv.Inventory)-nForeign, nForeign)
				if changed {
					resp.Msg += fmt.Sprintf(", SDE updated (%d adds, %d removes)",
						len(dskeyStatus.LocalAdds), len(dskeyStatus.LocalRemoves))
				}
			}

		case "resync":
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}
			sdcmd := &SynchedDataCmd{
				Cmd:      "resync",
				Zone:     amp.Zone,
				Response: make(chan *SynchedDataCmdResponse, 1),
			}
			conf.InternalMp.MsgQs.SynchedDataCmd <- sdcmd
			select {
			case response := <-sdcmd.Response:
				resp.Msg = response.Msg
				resp.Error = response.Error
				resp.ErrorMsg = response.ErrorMsg
			case <-time.After(10 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for resync"
			}
			resp.Status = "ok"

		case "send-rfi":
			switch amp.MessageType {
			case AgentMsgRfi:
				conf.InternalMp.MsgQs.Command <- &AgentMgmtPostPlus{
					amp,
					rch,
				}
				select {
				case r := <-rch:
					resp = *r
					resp.Status = "ok"
				case <-time.After(30 * time.Second):
					resp.Error = true
					resp.ErrorMsg = "timeout waiting for RFI response"
				}
			default:
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("send-rfi requires MessageType RFI, got %q", AgentMsgToString[amp.MessageType])
			}

		case "parentsync-status":
			lem := conf.InternalMp.LeaderElectionManager
			if lem == nil {
				resp.Error = true
				resp.ErrorMsg = "leader election manager not initialized"
				return
			}
			status := lem.GetParentSyncStatus(amp.Zone, zd.ZoneData, hdb, &Imr{conf.Config.Internal.ImrEngine}, conf.InternalMp.AgentRegistry)
			resp.Data = status
			resp.Msg = fmt.Sprintf("Parent sync status for zone %s", amp.Zone)

		case "parentsync-election":
			lem := conf.InternalMp.LeaderElectionManager
			if lem == nil {
				resp.Error = true
				resp.ErrorMsg = "leader election manager not initialized"
				return
			}
			// Route to group election if zone belongs to a provider group
			ar := conf.InternalMp.AgentRegistry
			if ar != nil && ar.ProviderGroupManager != nil {
				pg := ar.ProviderGroupManager.GetGroupForZone(amp.Zone)
				if pg != nil {
					lem.StartGroupElection(pg.GroupHash, pg.Members, pg.Zones)
					resp.Msg = fmt.Sprintf("Group election started for zone %s (group %s)", amp.Zone, pg.GroupHash[:8])
					return
				}
			}
			// No provider group — per-zone election
			configured := lem.configuredPeers(amp.Zone)
			operational := 0
			if lem.operationalPeersFunc != nil {
				operational = lem.operationalPeersFunc(amp.Zone)
			}
			if configured > 0 && operational < configured {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("cannot start election: only %d of %d configured peers are operational", operational, configured)
				return
			}
			lem.StartElection(amp.Zone, configured)
			resp.Msg = fmt.Sprintf("Election started for zone %s with %d peers", amp.Zone, configured)

		case "parentsync-inquire":
			rawImr := tdns.Globals.ImrEngine
			if rawImr == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR engine not available"
				return
			}
			imr := &Imr{rawImr}
			if imr.Cache == nil {
				resp.Error = true
				resp.ErrorMsg = "IMR cache not available"
				return
			}
			sak, err := hdb.GetSig0Keys(string(amp.Zone), tdns.Sig0StateActive)
			if err != nil || len(sak.Keys) == 0 {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("no active SIG(0) key for zone %s", amp.Zone)
				return
			}
			keyid := uint16(sak.Keys[0].KeyRR.KeyTag())
			keyState, extra, err := queryParentKeyStateDetailed(hdb, imr, string(amp.Zone), keyid)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("KeyState inquiry failed: %v", err)
				return
			}
			resp.Data = map[string]interface{}{
				"zone":       string(amp.Zone),
				"keyid":      keyid,
				"state":      keyState,
				"state_name": edns0.KeyStateToString(keyState),
				"extra_text": extra,
			}
			resp.Msg = fmt.Sprintf("Parent says: %s", edns0.KeyStateToString(keyState))

		case "parentsync-bootstrap":
			lem := conf.InternalMp.LeaderElectionManager
			if lem == nil {
				resp.Error = true
				resp.ErrorMsg = "leader election manager not initialized"
				return
			}
			if !lem.IsLeader(amp.Zone) {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("this agent is not the delegation sync leader for %s", amp.Zone)
				return
			}
			sak, err := hdb.GetSig0Keys(string(amp.Zone), tdns.Sig0StateActive)
			if err != nil || len(sak.Keys) == 0 {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("no active SIG(0) key for zone %s", amp.Zone)
				return
			}
			keyid := uint16(sak.Keys[0].KeyRR.KeyTag())
			algorithm := sak.Keys[0].KeyRR.Algorithm
			go conf.ParentSyncAfterKeyPublication(amp.Zone, string(amp.Zone), keyid, algorithm)
			resp.Msg = fmt.Sprintf("Bootstrap triggered for zone %s (keyid %d), running async", amp.Zone, keyid)

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
			// Build response with cache metadata
			entry := map[string]interface{}{
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

			// Collect all cache entries related to this identity's discovery names
			var entries []map[string]interface{}
			idCanon := strings.ToLower(identity)
			for item := range imr.Cache.RRsets.IterBuffered() {
				cr := item.Val
				name := strings.ToLower(cr.Name)
				if name != idCanon && !strings.HasSuffix(name, "."+idCanon) {
					continue
				}
				entry := map[string]interface{}{
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

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown agent command: %s", amp.Command)
			resp.Error = true
		}
	}
}

func (conf *Config) APIagentDebug() func(w http.ResponseWriter, r *http.Request) {
	if conf.InternalMp.MsgQs.DebugCommand == nil {
		lgApi.Error("DebugCommand channel is not set, cannot forward debug commands, fatal")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentMgmtResponse{
			Time:     time.Now(),
			Msg:      "Hi there! Using debug commands are we?",
			Identity: AgentId(conf.Config.MultiProvider.Identity),
		}
		decoder := json.NewDecoder(r.Body)
		var amp AgentMgmtPost
		err := decoder.Decode(&amp)

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			sanitizedResp := tdns.SanitizeForJSON(resp)
			err := json.NewEncoder(w).Encode(sanitizedResp)
			if err != nil {
				lgApi.Error("error encoding agent debug response", "err", err)
			}
		}()

		if err != nil {
			lgApi.Warn("error decoding /agent/debug post", "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		lgApi.Debug("received /agent/debug request", "command", amp.Command, "messagetype", AgentMsgToString[amp.MessageType], "from", r.RemoteAddr)

		rch := make(chan *AgentMgmtResponse, 1)

		switch amp.Command {
		case "send-notify", "send-rfi":
			// XXX: this is a bit bass-ackwards, in the debug case we're not using
			// amp.Command but rather amp.MessageType.
			switch amp.MessageType {
			case AgentMsgNotify, AgentMsgStatus, AgentMsgRfi:
				resp.Status = "ok"
				conf.InternalMp.MsgQs.DebugCommand <- &AgentMgmtPostPlus{
					amp,
					rch,
				}
				select {
				case r := <-rch:
					resp = *r
					resp.Status = "ok"

				case <-time.After(10 * time.Second):
					lgApi.Warn("no response from send-notify after 10 seconds")
					resp.Error = true
					resp.ErrorMsg = "No response from CommandHandler after 10 seconds, state unknown"
				}

			default:
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Unknown debug message type: %q", AgentMsgToString[amp.MessageType])
			}

		case "dump-agentregistry":
			resp.Status = "ok"
			ar := conf.InternalMp.AgentRegistry
			keys := ar.S.Keys()
			lgApi.Debug("dump-agentregistry", "keys", keys)
			for _, key := range keys {
				if agent, exists := ar.S.Get(key); exists {
					lgApi.Debug("agent registry entry", "identity", agent.Identity)
				}
			}
			lgApi.Debug("dump-agentregistry", "numShards", ar.S.NumShards())

			regs := map[AgentId]*Agent{}
			for _, key := range keys {
				if agent, exists := ar.S.Get(key); exists {
					tmp := tdns.SanitizeForJSON(agent)
					regs[key] = tmp.(*Agent)
				}
			}
			resp.AgentRegistry = &AgentRegistry{
				RegularS:       regs,
				RemoteAgents:   ar.RemoteAgents,
				LocalAgent:     ar.LocalAgent,
				LocateInterval: ar.LocateInterval,
			}

		case "dump-zonedatarepo":
			sdcmd := &SynchedDataCmd{
				Cmd:      "dump-zonedatarepo",
				Zone:     amp.Zone,
				Response: make(chan *SynchedDataCmdResponse, 1),
			}
			conf.InternalMp.MsgQs.SynchedDataCmd <- sdcmd
			select {
			case response := <-sdcmd.Response:
				resp.Msg = response.Msg
				resp.ZoneDataRepo = response.ZDR

				// Include per-zone KEYSTATE health status
				ksStatus := make(map[ZoneName]KeystateInfo)
				for zone := range response.ZDR {
					if zd, exists := Zones.Get(string(zone)); exists {
						ksStatus[zone] = KeystateInfo{
							OK:        zd.GetKeystateOK(),
							Error:     zd.GetKeystateError(),
							Timestamp: zd.GetKeystateTime().Format(time.RFC3339),
						}
					}
				}
				resp.KeystateStatus = ksStatus
			case <-time.After(2 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "No response from SynchedDataCmd after 2 seconds, state unknown"
			}

		case "show-key-inventory":
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required for show-key-inventory"
				return
			}
			zd, exists := Zones.Get(string(amp.Zone))
			if !exists {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("zone %q not found", amp.Zone)
				return
			}
			inv := zd.GetLastKeyInventory()
			if inv == nil {
				resp.Msg = fmt.Sprintf("No key inventory received yet for zone %s", amp.Zone)
			} else {
				resp.Data = inv
				resp.Msg = fmt.Sprintf("Key inventory for zone %s: %d keys (received %s from %s)",
					amp.Zone, len(inv.Inventory),
					inv.Received.Format("15:04:05"),
					inv.SenderID)
			}

		case "resync":
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}
			sdcmd := &SynchedDataCmd{
				Cmd:      "resync",
				Zone:     amp.Zone,
				Response: make(chan *SynchedDataCmdResponse, 1),
			}
			conf.InternalMp.MsgQs.SynchedDataCmd <- sdcmd
			select {
			case response := <-sdcmd.Response:
				resp.Msg = response.Msg
				resp.Error = response.Error
				resp.ErrorMsg = response.ErrorMsg
			case <-time.After(10 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for resync"
			}
			resp.Status = "ok"

		// HSYNC debug commands (Phase 5)
		case "hsync-chunk-send":
			resp.Msg = "CHUNK send not yet implemented - requires DNS transport setup"
			resp.Status = "ok"

		case "hsync-chunk-recv":
			resp.Msg = "CHUNK receive log not yet implemented - requires message logging"
			resp.Status = "ok"

		case "hsync-init-db":
			if conf.InternalMp.HsyncDB == nil {
				resp.Error = true
				resp.ErrorMsg = "HsyncDB not available"
				return
			}
			if err := conf.InternalMp.HsyncDB.InitHsyncTables(); err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("InitHsyncTables failed: %v", err)
				return
			}
			resp.Msg = "HSYNC database tables initialized successfully"
			resp.Status = "ok"

		case "hsync-sync-state":
			// Show sync state for a zone
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}

			// Get sync state from ZoneDataRepo via SynchedDataCmd
			sdcmd := &SynchedDataCmd{
				Cmd:      "get-zone-state",
				Zone:     amp.Zone,
				Response: make(chan *SynchedDataCmdResponse, 1),
			}
			conf.InternalMp.MsgQs.SynchedDataCmd <- sdcmd

			select {
			case response := <-sdcmd.Response:
				if response.Error {
					resp.Error = true
					resp.ErrorMsg = response.ErrorMsg
				} else {
					resp.Msg = fmt.Sprintf("Sync state for zone %q", amp.Zone)
					resp.Data = map[string]interface{}{
						"zone":           amp.Zone,
						"zone_data_repo": response.ZDR,
						"message":        response.Msg,
					}
				}
				resp.Status = "ok"
			case <-time.After(2 * time.Second):
				resp.Error = true
				resp.ErrorMsg = "timeout waiting for sync state response"
				resp.Status = "timeout"
			}

		case "show-combiner-data":
			// Show combiner's local modifications store
			zone := amp.Zone
			combinerData := make(map[string]map[string]map[string][]string)

			if zone != "" {
				// Single zone
				zd, exists := Zones.Get(string(zone))
				if !exists {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("zone %q not found", zone)
					return
				}
				if zd.MP != nil && zd.MP.CombinerData != nil {
					zoneData := make(map[string]map[string][]string)
					for item := range zd.MP.CombinerData.IterBuffered() {
						ownerName := item.Key
						ownerData := item.Val
						rrTypeData := make(map[string][]string)
						for _, rrtype := range ownerData.RRtypes.Keys() {
							rrset, _ := ownerData.RRtypes.Get(rrtype)
							var rrs []string
							for _, rr := range rrset.RRs {
								rrs = append(rrs, rr.String())
							}
							rrTypeData[dns.TypeToString[rrtype]] = rrs
						}
						zoneData[ownerName] = rrTypeData
					}
					combinerData[string(zone)] = zoneData
				}
			} else {
				// All zones
				for _, zd := range Zones.Items() {
					if zd.MP != nil && zd.MP.CombinerData != nil {
						zoneData := make(map[string]map[string][]string)
						for item := range zd.MP.CombinerData.IterBuffered() {
							ownerName := item.Key
							ownerData := item.Val
							rrTypeData := make(map[string][]string)
							for _, rrtype := range ownerData.RRtypes.Keys() {
								rrset, _ := ownerData.RRtypes.Get(rrtype)
								var rrs []string
								for _, rr := range rrset.RRs {
									rrs = append(rrs, rr.String())
								}
								rrTypeData[dns.TypeToString[rrtype]] = rrs
							}
							zoneData[ownerName] = rrTypeData
						}
						combinerData[zd.ZoneName] = zoneData
					}
				}
			}

			resp.Data = map[string]interface{}{
				"combiner_data": combinerData,
			}
			resp.Msg = fmt.Sprintf("Combiner data retrieved for %d zone(s)", len(combinerData))
			resp.Status = "ok"

		case "send-sync-to":
			// Send a real SYNC to a remote agent
			if amp.AgentId == "" {
				resp.Error = true
				resp.ErrorMsg = "target agent ID (--to) is required"
				return
			}
			if amp.Zone == "" {
				resp.Error = true
				resp.ErrorMsg = "zone is required"
				return
			}

			// Check if TransportManager is available
			if conf.InternalMp.TransportManager == nil {
				resp.Error = true
				resp.ErrorMsg = "TransportManager not available (DNS transport not configured)"
				return
			}

			// Get peer from agent registry
			agent, exists := conf.InternalMp.AgentRegistry.S.Get(amp.AgentId)
			if !exists {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("target agent %q not found in registry", amp.AgentId)
				return
			}

			// Validate RRs
			for _, rrStr := range amp.RRs {
				_, err := dns.NewRR(rrStr)
				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("failed to parse RR %q: %v", rrStr, err)
					return
				}
			}

			// Convert agent to transport peer
			peer := conf.InternalMp.MPTransport.SyncPeerFromAgent(agent)

			// Create sync request
			syncReq := &transport.SyncRequest{
				SenderID:       conf.Config.MultiProvider.Identity,
				Zone:           string(amp.Zone),
				SyncType:       transport.SyncTypeNS, // Default to NS, could be detected from RRs
				Records:        groupRRStringsByOwner(amp.RRs),
				DistributionID: fmt.Sprintf("debug-send-sync-%d", time.Now().Unix()),
				MessageType:    "sync",
			}

			lgApi.Info("sending sync to agent", "target", amp.AgentId, "zone", amp.Zone, "rrs", len(amp.RRs))

			// Send sync with fallback
			ctx := context.Background()
			syncResp, err := conf.InternalMp.MPTransport.SendSyncWithFallback(ctx, peer, syncReq)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("sync failed: %v", err)
			} else {
				resp.Msg = fmt.Sprintf("SYNC sent successfully to %q (distribution: %s)", amp.AgentId, syncReq.DistributionID)
				resp.Data = map[string]interface{}{
					"distribution_id": syncReq.DistributionID,
					"target":          amp.AgentId,
					"zone":            amp.Zone,
					"rr_count":        len(amp.RRs),
					"status":          syncResp.Status,
					"message":         syncResp.Message,
				}
			}
			resp.Status = "ok"

		case "queue-status":
			// Show reliable message queue status and pending messages
			if conf.InternalMp.TransportManager == nil {
				resp.Error = true
				resp.ErrorMsg = "TransportManager not available"
				return
			}

			stats := conf.InternalMp.MPTransport.GetQueueStats()
			pending := conf.InternalMp.MPTransport.GetQueuePendingMessages()

			resp.Data = map[string]interface{}{
				"stats":    stats,
				"messages": pending,
			}
			resp.Msg = fmt.Sprintf("Queue: %d pending, %d delivered, %d failed, %d expired",
				stats.TotalPending, stats.TotalDelivered, stats.TotalFailed, stats.TotalExpired)
			resp.Status = "ok"

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown debug command: %q", amp.Command)
		}
	}
}

func (conf *Config) APIbeat() func(w http.ResponseWriter, r *http.Request) {
	if conf.InternalMp.MsgQs.Beat == nil {
		lgApi.Error("AgentBeatQ channel is not set, cannot forward heartbeats, fatal")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentBeatResponse{
			Time: time.Now(),
			Msg:  "Hi there!",
		}
		decoder := json.NewDecoder(r.Body)
		var abp AgentBeatPost
		err := decoder.Decode(&abp)

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("error encoding beat response", "err", err)
			}
		}()

		if err != nil {
			lgApi.Warn("error decoding beat post", "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		resp.YourIdentity = abp.MyIdentity
		resp.MyIdentity = AgentId(conf.Config.LocalIdentity())

		switch abp.MessageType {
		case AgentMsgBeat:
			resp.Status = "ok"
			conf.InternalMp.MsgQs.Beat <- &AgentMsgReport{
				Transport:    "API",
				MessageType:  abp.MessageType,
				Identity:     abp.MyIdentity,
				BeatInterval: abp.MyBeatInterval,
				Msg:          &abp,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown heartbeat type: %q from %s", AgentMsgToString[abp.MessageType], abp.MyIdentity)
		}
	}
}

// This is the agent-to-agent sync API hello handler.
func (conf *Config) APIhello() func(w http.ResponseWriter, r *http.Request) {
	if conf.InternalMp.MsgQs.Hello == nil {
		lgApi.Error("HelloQ channel is not set, cannot forward HELLO msgs, fatal")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		lgApi.Debug("received /hello request", "from", r.RemoteAddr)
		decoder := json.NewDecoder(r.Body)
		var ahp AgentHelloPost
		err := decoder.Decode(&ahp)

		resp := AgentHelloResponse{
			Time:       time.Now(),
			MyIdentity: AgentId(conf.Config.LocalIdentity()),
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				lgApi.Error("error encoding hello response", "err", err)
			}
		}()

		if err != nil {
			lgApi.Warn("error decoding /hello post", "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		// Cannot use ahp.MyIdentity until we know that the JSON unmarshalling has succeeded.
		resp.YourIdentity = ahp.MyIdentity

		needed, errmsg, err := conf.InternalMp.AgentRegistry.EvaluateHello(&ahp)
		if err != nil {
			lgApi.Warn("error evaluating hello", "err", err)
			resp.Error = true
			resp.ErrorMsg = errmsg
			return
		}

		if needed {
			lgApi.Info("hello accepted, HSYNC RRset includes both identities", "zone", ahp.Zone)
			resp.Msg = fmt.Sprintf("Hello there, %s! Nice of you to call on us. I'm a TDNS agent with identity %q and we do share responsibility for zone %q",
				ahp.MyIdentity, conf.Config.LocalIdentity(), ahp.Zone)
		} else {
			lgApi.Warn("hello rejected, HSYNC RRset does not include both identities", "zone", ahp.Zone)
			resp.Error = true
			resp.ErrorMsg = errmsg
			return
		}

		switch ahp.MessageType {
		case AgentMsgHello:
			resp.Status = "ok" // important
			conf.InternalMp.MsgQs.Hello <- &AgentMsgReport{
				Transport:   "API",
				MessageType: ahp.MessageType,
				Identity:    ahp.MyIdentity,
				Msg:         &ahp,
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown hello type: %q from %s", AgentMsgToString[ahp.MessageType], ahp.MyIdentity)
		}
	}
}

// APIsyncPing is the HSYNC peer ping handler on the sync API router (/sync/ping).
func (conf *Config) APIsyncPing() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentPingResponse{
			Time:       time.Now(),
			MyIdentity: AgentId(conf.Config.LocalIdentity()),
		}
		decoder := json.NewDecoder(r.Body)
		var app AgentPingPost
		err := decoder.Decode(&app)

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			if encErr := json.NewEncoder(w).Encode(resp); encErr != nil {
				lgApi.Error("error encoding ping response", "err", encErr)
			}
		}()

		if err != nil {
			lgApi.Warn("error decoding /sync/ping post", "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		if app.Nonce == "" {
			resp.Error = true
			resp.ErrorMsg = "ping nonce must not be empty"
			return
		}

		resp.YourIdentity = app.MyIdentity
		resp.Nonce = app.Nonce
		resp.Status = "ok"

		if conf.InternalMp.MsgQs != nil && conf.InternalMp.MsgQs.Ping != nil {
			conf.InternalMp.MsgQs.Ping <- &AgentMsgReport{
				Transport:   "API",
				MessageType: AgentMsgPing,
				Identity:    app.MyIdentity,
				Msg:         &app,
			}
		}
	}
}

func (conf *Config) APImsg() func(w http.ResponseWriter, r *http.Request) {
	if conf.InternalMp.MsgQs.Msg == nil {
		lgApi.Error("msgQ channel is not set, cannot forward API msgs, fatal")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := AgentMsgResponse{
			Time: time.Now(),
			Msg:  "Hi there!",
		}
		decoder := json.NewDecoder(r.Body)
		var amp AgentMsgPost
		err := decoder.Decode(&amp)

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			lgApi.Debug("encoding msg response", "resp", resp)
			respData, err := json.Marshal(resp)
			if err != nil {
				lgApi.Error("error marshaling msg response", "err", err)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Error marshaling response: %v", err)
				respData, _ = json.Marshal(resp) // Attempt to marshal the error response
			}
			lgApi.Debug("msg response data", "data", string(respData))
			_, err = w.Write(respData)
			if err != nil {
				lgApi.Error("error writing msg response", "err", err)
			}
		}()

		if err != nil {
			lgApi.Warn("error decoding /msg post", "err", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Invalid request format: %v", err)
			return
		}

		lgApi.Debug("received /msg request", "messageType", amp.MessageType, "from", r.RemoteAddr, "originator", amp.OriginatorID)

		switch amp.MessageType {
		case AgentMsgNotify, AgentMsgStatus, AgentMsgRfi:
			resp.Status = "ok"
			var cresp = make(chan *AgentMsgResponse, 1)

			select {
			case conf.InternalMp.MsgQs.Msg <- &AgentMsgPostPlus{
				AgentMsgPost: amp,
				Response:     cresp,
			}:
				select {
				case r := <-cresp:
					lgApi.Debug("received response from msg handler", "resp", r)
					if r.Error {
						lgApi.Warn("error processing message", "originator", amp.OriginatorID, "err", r.ErrorMsg)
						resp.Error = true
						resp.ErrorMsg = r.ErrorMsg
						resp.Status = "error"
					} else {
						resp = *r
						resp.Status = "ok"
					}
					return

				case <-time.After(2 * time.Second):
					lgApi.Warn("no response received for message within timeout", "originator", amp.OriginatorID)
					resp.Error = true
					resp.ErrorMsg = "No response received within timeout period"
				}
			default:
				lgApi.Warn("msg response channel is blocked, skipping message", "originator", amp.OriginatorID)
				resp.Error = true
				resp.ErrorMsg = "Msg channel is blocked"
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown message type: %q from %s", AgentMsgToString[amp.MessageType], amp.OriginatorID)
		}
	}
}
