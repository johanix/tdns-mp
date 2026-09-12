/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * mpcli HSYNC commands. These post to /agent/hsync (handled by
 * tdns-mp's APIagentHsync) and were ported from tdns/v2/cli/hsync_cmds.go
 * and tdns/v2/cli/hsync_debug_cmds.go.
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	tdns "github.com/johanix/tdns/v2"
	tdnscli "github.com/johanix/tdns/v2/cli"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"
)

var (
	hsyncTransport string
	hsyncPeerID    string
	hsyncLimit     int
	hsyncAgentID   string
	hsyncResolver  string
)

// newHsyncCmd builds the "agent hsync" subtree of HSYNC state-reporting
// subcommands.
func newHsyncCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "hsync",
		Short: "HSYNC state-reporting commands",
		Long:  `Query HSYNC state stored in the agent's KeyDB and AgentRegistry.`,
	}
	c.AddCommand(newHsyncZoneStatusCmd(kind))
	c.AddCommand(newHsyncSyncOpsCmd(kind))
	c.AddCommand(newHsyncConfirmationsCmd(kind))
	c.AddCommand(newHsyncTransportEventsCmd(kind))
	c.AddCommand(newHsyncMetricsCmd(kind))
	c.AddCommand(newHsyncAgentStatusCmd(kind))
	c.AddCommand(newHsyncLocateCmd(kind))
	c.AddCommand(newHsyncSendHelloCmd(kind))
	c.AddCommand(newHsyncQueryCmd(kind))
	return c
}

// SendAgentHsyncCommand posts an AgentMgmtPost to /agent/hsync on the
// instance cmd's tree targets and returns the parsed AgentMgmtResponse.
func SendAgentHsyncCommand(cmd *cobra.Command, req *AgentMgmtPost) (*AgentMgmtResponse, error) {
	api, err := GetApiClientForCmd(cmd, true)
	if err != nil {
		return nil, fmt.Errorf("error getting API client: %v", err)
	}

	_, buf, err := api.RequestNG("POST", "/agent/hsync", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}

	var amr AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if amr.Error {
		return &amr, fmt.Errorf("%s", amr.ErrorMsg)
	}

	return &amr, nil
}

func newHsyncZoneStatusCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "zonestatus",
		Short: "Show HSYNC status for a zone",
		Run: func(cmd *cobra.Command, args []string) {
			tdnscli.PrepArgs("zonename")

			resp, err := SendAgentHsyncCommand(cmd, &AgentMgmtPost{
				Command: "hsync-zonestatus",
				Zone:    ZoneName(dns.Fqdn(tdns.Globals.Zonename)),
			})
			if err != nil {
				log.Fatalf("Error: %v", err)
			}

			PrintHsyncRRs(AgentId(resp.Identity), resp.HsyncRRs)

			if tdns.Globals.Verbose && resp.ZoneAgentData != nil {
				fmt.Printf("\nZone Agent Data:\n")
				fmt.Printf("  My Upstream: %s\n", resp.ZoneAgentData.MyUpstream)
				fmt.Printf("  My Downstreams: %v\n", resp.ZoneAgentData.MyDownstreams)
			}

			if resp.ZoneAgentData != nil && len(resp.ZoneAgentData.Agents) > 0 {
				fmt.Printf("\n%s Remote Agents:\n", tdns.Globals.Zonename)
				for _, agent := range resp.ZoneAgentData.Agents {
					if agent.Identity == resp.Identity {
						continue
					}
					if err := PrintHsyncAgent(agent, true); err != nil {
						log.Printf("Error printing agent: %v", err)
					}
					fmt.Println()
				}
			} else {
				fmt.Printf("\nNo remote agents for zone %q found in the AgentRegistry\n", tdns.Globals.Zonename)
			}
		},
	}
	c.Flags().StringVarP(&hsyncTransport, "transport", "T", "", "Transport to show, default both api and dns")
	return c
}

func newHsyncSyncOpsCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "sync-ops",
		Short: "Show HSYNC sync operations",
		Long: `Display sync operations tracked in the database.
Shows operation details, status, and timestamps.`,
		Run: func(cmd *cobra.Command, args []string) {
			resp, err := SendAgentHsyncCommand(cmd, &AgentMgmtPost{
				Command: "hsync-sync-ops",
				Zone:    ZoneName(dns.Fqdn(tdns.Globals.Zonename)),
			})
			if err != nil {
				log.Fatalf("Error: %v", err)
			}

			if len(resp.HsyncSyncOps) == 0 {
				fmt.Println("No sync operations found")
				return
			}

			fmt.Printf("Sync Operations (%d):\n\n", len(resp.HsyncSyncOps))

			var lines []string
			if tdns.Globals.ShowHeaders {
				lines = append(lines, "Distribution ID|Zone|Type|Direction|Status|Created|Sender|Receiver")
			}
			for _, op := range resp.HsyncSyncOps {
				corrID := op.DistributionID
				if len(corrID) > 16 {
					corrID = corrID[:16] + "..."
				}
				lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
					corrID,
					op.ZoneName,
					op.SyncType,
					op.Direction,
					op.Status,
					op.CreatedAt.Format("2006-01-02 15:04"),
					op.SenderID,
					op.ReceiverID))
			}
			fmt.Println(columnize.SimpleFormat(lines))
		},
	}
	return c
}

func newHsyncConfirmationsCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "confirmations",
		Short: "Query HSYNC confirmations",
		Long:  `Display confirmation records for sync operations.`,
		Run: func(cmd *cobra.Command, args []string) {
			resp, err := SendAgentHsyncCommand(cmd, &AgentMgmtPost{
				Command: "hsync-confirmations",
			})
			if err != nil {
				log.Fatalf("Error: %v", err)
			}

			if len(resp.HsyncConfirmations) == 0 {
				fmt.Println("No confirmations found")
				return
			}

			fmt.Printf("Confirmations (%d):\n\n", len(resp.HsyncConfirmations))

			var lines []string
			if tdns.Globals.ShowHeaders {
				lines = append(lines, "Distribution ID|Confirmer|Status|Message|Confirmed At")
			}
			for _, c := range resp.HsyncConfirmations {
				corrID := c.DistributionID
				if len(corrID) > 16 {
					corrID = corrID[:16] + "..."
				}
				msg := c.Message
				if len(msg) > 30 {
					msg = msg[:30] + "..."
				}
				lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s",
					corrID,
					c.ConfirmerID,
					c.Status,
					msg,
					c.ConfirmedAt.Format("2006-01-02 15:04")))
			}
			fmt.Println(columnize.SimpleFormat(lines))
		},
	}
	return c
}

func newHsyncTransportEventsCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "events",
		Short: "Show HSYNC transport events",
		Long:  `Display recent transport events for debugging connectivity issues.`,
		Run: func(cmd *cobra.Command, args []string) {
			resp, err := SendAgentHsyncCommand(cmd, &AgentMgmtPost{
				Command: "hsync-transport-events",
				AgentId: AgentId(hsyncPeerID),
				Data:    map[string]interface{}{"limit": hsyncLimit},
			})
			if err != nil {
				log.Fatalf("Error: %v", err)
			}

			if len(resp.HsyncEvents) == 0 {
				fmt.Println("No transport events found")
				return
			}

			fmt.Printf("Transport Events (%d):\n\n", len(resp.HsyncEvents))

			var lines []string
			if tdns.Globals.ShowHeaders {
				lines = append(lines, "Time|Peer|Event Type|Transport|Direction|Success|Error")
			}
			for _, evt := range resp.HsyncEvents {
				success := "Y"
				if !evt.Success {
					success = "N"
				}
				errMsg := evt.ErrorMessage
				if len(errMsg) > 30 {
					errMsg = errMsg[:30] + "..."
				}
				lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
					evt.EventTime.Format("15:04:05"),
					evt.PeerID,
					evt.EventType,
					evt.Transport,
					evt.Direction,
					success,
					errMsg))
			}
			fmt.Println(columnize.SimpleFormat(lines))
		},
	}
	c.Flags().StringVarP(&hsyncPeerID, "peer", "p", "", "Filter by peer ID")
	c.Flags().IntVarP(&hsyncLimit, "limit", "n", 100, "Maximum number of events to show")
	return c
}

func newHsyncMetricsCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "metrics",
		Short: "Show HSYNC operational metrics",
		Long:  `Display aggregated operational metrics for HSYNC operations.`,
		Run: func(cmd *cobra.Command, args []string) {
			resp, err := SendAgentHsyncCommand(cmd, &AgentMgmtPost{
				Command: "hsync-metrics",
			})
			if err != nil {
				log.Fatalf("Error: %v", err)
			}

			if resp.HsyncMetrics == nil {
				fmt.Println("No metrics available")
				return
			}

			m := resp.HsyncMetrics
			fmt.Println("HSYNC Operational Metrics:")
			fmt.Println()
			fmt.Printf("  Syncs Sent:      %d\n", m.SyncsSent)
			fmt.Printf("  Syncs Received:  %d\n", m.SyncsReceived)
			fmt.Printf("  Syncs Confirmed: %d\n", m.SyncsConfirmed)
			fmt.Printf("  Syncs Failed:    %d\n", m.SyncsFailed)
			fmt.Println()
			fmt.Printf("  Beats Sent:      %d\n", m.BeatsSent)
			fmt.Printf("  Beats Received:  %d\n", m.BeatsReceived)
			fmt.Printf("  Beats Missed:    %d\n", m.BeatsMissed)
			fmt.Println()
			fmt.Printf("  API Operations:  %d\n", m.APIOperations)
			fmt.Printf("  DNS Operations:  %d\n", m.DNSOperations)
			if m.AvgLatency > 0 {
				fmt.Printf("  Avg Latency:     %dms\n", m.AvgLatency)
				fmt.Printf("  Max Latency:     %dms\n", m.MaxLatency)
			}
		},
	}
	return c
}

func newHsyncAgentStatusCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "agentstatus",
		Short: "Show HSYNC status for an agent",
		Run: func(cmd *cobra.Command, args []string) {
			tdns.Globals.AgentId = tdns.AgentId(hsyncAgentID)
			tdnscli.PrepArgs("agentid")

			amr, err := SendAgentMgmtCmd(cmd, &AgentMgmtPost{
				Command: "hsync-agentstatus",
				AgentId: AgentId(string(tdns.Globals.AgentId)),
			})
			if err != nil {
				log.Fatalf("Error sending agent management command: %v", err)
			}

			if amr.Error {
				log.Fatalf("Error response from agent %q: %s",
					tdns.Globals.AgentId, amr.ErrorMsg)
			}

			if len(amr.Agents) > 0 {
				for _, agent := range amr.Agents {
					if err := PrintHsyncAgent(agent, true); err != nil {
						log.Printf("Error printing agent: %v", err)
					}
					fmt.Println()
				}
			} else {
				fmt.Printf("\nNo remote agent with identity %q found in the AgentRegistry\n",
					tdns.Globals.AgentId)
			}
		},
	}
	c.Flags().StringVarP(&hsyncAgentID, "agentid", "", "", "Remote agent identity to show")
	return c
}

func newHsyncLocateCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "locate <agent-identity>",
		Short: "Locate and attempt to contact a remote agent",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			tdnscli.PrepArgs("zonename")

			amr, err := SendAgentMgmtCmd(cmd, &AgentMgmtPost{
				Command: "hsync-locate",
				AgentId: AgentId(dns.Fqdn(args[0])),
				Zone:    ZoneName(tdns.Globals.Zonename),
			})
			if err != nil {
				log.Fatalf("Error: %v", err)
			}

			if amr.Error {
				log.Fatalf("API error: %s", amr.ErrorMsg)
			}

			if len(amr.Agents) > 0 {
				agent := amr.Agents[0]
				fmt.Printf("Located agent: %s\n", agent.Identity)
				if err := PrintHsyncAgent(agent, false); err != nil {
					log.Printf("Error printing agent: %v", err)
				}
			}
		},
	}
	return c
}

func newHsyncSendHelloCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "send-hello",
		Short: "Send a hello message to a remote agent",
		Long:  `Send a hello message to a remote agent via the running agent server.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			agentIdentity := AgentId(dns.Fqdn(args[0]))

			amr, err := SendAgentMgmtCmd(cmd, &AgentMgmtPost{
				Command: "hsync-send-hello",
				AgentId: agentIdentity,
			})
			if err != nil {
				log.Fatalf("Error: %v", err)
			}

			if amr.Error {
				fmt.Printf("Error: %s\n", amr.ErrorMsg)
				return
			}

			fmt.Printf("HELLO response from %s:\n", agentIdentity)
			fmt.Printf("  %s\n", amr.Msg)
		},
	}
	return c
}

func newHsyncQueryCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "query",
		Short: "Query HSYNC RRset for a zone via DNS",
		Run: func(cmd *cobra.Command, args []string) {
			tdnscli.PrepArgs("zonename")

			zonename := dns.Fqdn(string(tdns.Globals.Zonename))

			resolver := hsyncResolver
			if resolver == "" {
				resolver = "8.8.8.8:53"
			}

			fmt.Printf("Querying HSYNC3 records for zone %s via %s\n\n",
				zonename, resolver)

			c := new(dns.Client)
			c.Timeout = 5 * time.Second

			m := new(dns.Msg)
			m.SetQuestion(zonename, core.TypeHSYNC3)
			m.SetEdns0(4096, true)

			r, rtt, err := c.Exchange(m, resolver)
			if err != nil {
				log.Fatalf("DNS query failed: %v", err)
			}

			fmt.Printf("Query completed in %v\n", rtt)
			fmt.Printf("Response code: %s\n", dns.RcodeToString[r.Rcode])
			fmt.Printf("Answer section (%d records):\n\n", len(r.Answer))

			if len(r.Answer) == 0 {
				fmt.Println("No HSYNC3 records found")
				return
			}

			var lines []string
			if tdns.Globals.ShowHeaders {
				lines = append(lines,
					"Owner|TTL|Class|Type|Label|Identity|Upstream")
			}
			for _, rr := range r.Answer {
				privRR, ok := rr.(*dns.PrivateRR)
				if !ok {
					fmt.Printf("  %s (not a PrivateRR)\n", rr.String())
					continue
				}
				hsync3, ok := privRR.Data.(*core.HSYNC3)
				if !ok {
					fmt.Printf("  %s (not HSYNC3 data)\n", rr.String())
					continue
				}
				lines = append(lines,
					fmt.Sprintf("%s|%d|IN|HSYNC3|%s|%s|%s",
						rr.Header().Name, rr.Header().Ttl,
						hsync3.Label, hsync3.Identity,
						hsync3.Upstream))
			}
			fmt.Println(columnize.SimpleFormat(lines))
		},
	}
	c.Flags().StringVarP(&hsyncResolver, "resolver", "", "", "Resolver address for DNS query (e.g. 8.8.8.8:53)")
	return c
}

// PrintHsyncRRs displays HSYNC3 RRs in tabular form, marking the local agent.
func PrintHsyncRRs(agentid AgentId, rrs []string) {
	fmt.Printf("%s  HSYNC RRset:\n", tdns.Globals.Zonename)
	var lines []string
	for _, rrstr := range rrs {
		rr, err := dns.NewRR(rrstr)
		if err != nil {
			log.Printf("Failed to parse HSYNC RR: %v", err)
			continue
		}
		privRR, ok := rr.(*dns.PrivateRR)
		if !ok {
			log.Printf("RR is not a PrivateRR: %v", rr)
			continue
		}
		hsync3RR, ok := privRR.Data.(*core.HSYNC3)
		if !ok {
			log.Printf("PrivateRR does not contain HSYNC3 data: %v", privRR)
			continue
		}
		fields := strings.Fields(rrstr)
		if AgentId(hsync3RR.Identity) == agentid {
			fields = append(fields, "(local agent)")
		}
		lines = append(lines, strings.Join(fields, "|"))
	}
	fmt.Println(columnize.SimpleFormat(lines))
}

// PrintHsyncAgent prints the management API's report of a remote agent.
func PrintHsyncAgent(agent *AgentInfo, showZones bool) error {
	fmt.Printf("Remote agent %q: state: %s\n", agent.Identity, AgentStateToString[agent.State])

	if showZones {
		var zones []string
		for zone := range agent.Zones {
			zones = append(zones, string(zone))
		}
		fmt.Printf(" * Zones shared with this agent: %v\n", zones)
	}

	// Per-mechanism state and addresses are `peer list` / `peer list -v`
	// (transport.Peer).
	return nil
}
