/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	tdnscli "github.com/johanix/tdns/v2/cli"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var AuditorCmd = &cobra.Command{
	Use:   "auditor",
	Short: "TDNS MP Auditor commands",
}

var AuditorZoneCmd = &cobra.Command{
	Use:   "zone",
	Short: "Auditor zone commands",
}

var auditorZoneListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured zones",
	Run:   func(cmd *cobra.Command, args []string) { tdnscli.RunZoneList("auditor", args) },
}

var auditorZoneMPListCmd = &cobra.Command{
	Use:   "mplist",
	Short: "List multi-provider zones with HSYNCPARAM details",
	Run:   func(cmd *cobra.Command, args []string) { tdnscli.RunZoneMPList("auditor", args) },
}

var auditorZoneReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Request re-loading a zone",
	Run:   func(cmd *cobra.Command, args []string) { tdnscli.RunZoneReload("auditor", args) },
}

var auditorZoneBumpCmd = &cobra.Command{
	Use:   "bump",
	Short: "Bump SOA serial and epoch (if any)",
	Run:   func(cmd *cobra.Command, args []string) { tdnscli.RunZoneBump("auditor", args) },
}

var auditorEventlogCmd = &cobra.Command{
	Use:   "eventlog",
	Short: "Audit event log commands",
}

var auditorEventlogListCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit events",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		req := AuditPost{Command: "eventlog-list"}

		zone, _ := cmd.Flags().GetString("zone")
		if zone != "" {
			req.Zone = dns.Fqdn(zone)
		}
		since, _ := cmd.Flags().GetString("since")
		if since != "" {
			req.Since = since
		}
		limit, _ := cmd.Flags().GetInt("last")
		if limit > 0 {
			req.Limit = limit
		} else {
			req.Limit = 50
		}

		resp, err := executeAuditRequest("eventlog-list", req)
		if err != nil {
			log.Fatalf("%v", err)
		}

		if len(resp.Events) == 0 {
			fmt.Println("No events found")
			return
		}

		fmt.Printf("%-20s  %-10s  %-25s  %-25s  %s\n",
			"Time", "Type", "Zone", "Originator", "Summary")
		fmt.Printf("%-20s  %-10s  %-25s  %-25s  %s\n",
			strings.Repeat("-", 20), strings.Repeat("-", 10),
			strings.Repeat("-", 25), strings.Repeat("-", 25),
			strings.Repeat("-", 40))
		for _, e := range resp.Events {
			timeStr := e.Time.Format("2006-01-02 15:04:05")
			fmt.Printf("%-20s  %-10s  %-25s  %-25s  %s\n",
				timeStr, e.EventType, e.Zone, e.Originator, e.Summary)
		}
	},
}

var auditorEventlogClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear audit events",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		req := AuditPost{Command: "eventlog-clear"}

		zone, _ := cmd.Flags().GetString("zone")
		if zone != "" {
			req.Zone = dns.Fqdn(zone)
		}
		olderThan, _ := cmd.Flags().GetString("older-than")
		if olderThan != "" {
			req.OlderThan = olderThan
		}
		all, _ := cmd.Flags().GetBool("all")
		req.All = all

		resp, err := executeAuditRequest("eventlog-clear", req)
		if err != nil {
			log.Fatalf("%v", err)
		}

		fmt.Println(resp.Msg)
	},
}

var auditorObservationsCmd = &cobra.Command{
	Use:   "observations",
	Short: "Show anomalies/observations detected by the auditor",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		req := AuditPost{Command: "observations"}
		zone, _ := cmd.Flags().GetString("zone")
		if zone != "" {
			req.Zone = dns.Fqdn(zone)
		}

		resp, err := executeAuditRequest("observations", req)
		if err != nil {
			log.Fatalf("%v", err)
		}

		if len(resp.Observations) == 0 {
			fmt.Println("No observations")
			return
		}

		fmt.Printf("%-20s  %-8s  %-25s  %-20s  %s\n",
			"Time", "Severity", "Zone", "Provider", "Message")
		for _, o := range resp.Observations {
			fmt.Printf("%-20s  %-8s  %-25s  %-20s  %s\n",
				o.Time.Format("2006-01-02 15:04:05"),
				o.Severity, o.Zone, o.Provider, o.Message)
		}
	},
}

// AuditPost mirrors the API request type.
type AuditPost struct {
	Command   string `json:"command"`
	Zone      string `json:"zone,omitempty"`
	Since     string `json:"since,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	OlderThan string `json:"older_than,omitempty"`
	All       bool   `json:"all,omitempty"`
}

// AuditResponse mirrors the API response type.
type AuditResponse struct {
	Status       string             `json:"status"`
	Msg          string             `json:"msg,omitempty"`
	Error        bool               `json:"error,omitempty"`
	ErrorMsg     string             `json:"error_msg,omitempty"`
	Zones        []AuditZoneSummary `json:"zones,omitempty"`
	Events       []AuditEvent       `json:"events,omitempty"`
	Observations []AuditObservation `json:"observations,omitempty"`
	Deleted      int64              `json:"deleted,omitempty"`
}

type AuditZoneSummary struct {
	Zone          string                         `json:"zone"`
	ProviderCount int                            `json:"provider_count"`
	ZoneSerial    uint32                         `json:"zone_serial,omitempty"`
	Providers     map[string]*AuditProviderState `json:"providers,omitempty"`
}

type AuditProviderState struct {
	Identity    string    `json:"identity"`
	Label       string    `json:"label"`
	IsSigner    bool      `json:"is_signer"`
	LastBeat    time.Time `json:"last_beat"`
	LastSync    time.Time `json:"last_sync"`
	GossipState string    `json:"gossip_state"`
}

type AuditEvent struct {
	Time        time.Time `json:"time"`
	Zone        string    `json:"zone"`
	Originator  string    `json:"originator"`
	DeliveredBy string    `json:"delivered_by"`
	EventType   string    `json:"event_type"`
	Summary     string    `json:"summary"`
	RRsAdded    int       `json:"rrs_added"`
	RRsRemoved  int       `json:"rrs_removed"`
	RRtypes     string    `json:"rrtypes"`
}

type AuditObservation struct {
	Time     time.Time `json:"time"`
	Severity string    `json:"severity"`
	Zone     string    `json:"zone"`
	Provider string    `json:"provider"`
	Message  string    `json:"message"`
}

func executeAuditRequest(cmdName string, req AuditPost) (*AuditResponse, error) {
	parent, _ := tdnscli.GetCommandContext(cmdName)

	api, err := tdnscli.GetApiClient(parent, true)
	if err != nil {
		return nil, fmt.Errorf("error getting API client: %w", err)
	}

	_, buf, err := api.RequestNG("POST", "/audit", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}

	var resp AuditResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if resp.Error {
		return nil, fmt.Errorf("API error: %s", resp.ErrorMsg)
	}

	return &resp, nil
}

func init() {
	auditorEventlogListCmd.Flags().StringP("zone", "z", "", "filter by zone")
	auditorEventlogListCmd.Flags().String("since", "", "events since (RFC3339)")
	auditorEventlogListCmd.Flags().Int("last", 50, "number of events to show")

	auditorEventlogClearCmd.Flags().StringP("zone", "z", "", "clear events for zone")
	auditorEventlogClearCmd.Flags().String("older-than", "", "clear events older than duration (e.g. 24h)")
	auditorEventlogClearCmd.Flags().Bool("all", false, "clear all events")

	auditorObservationsCmd.Flags().StringP("zone", "z", "", "filter by zone")

	AuditorZoneCmd.AddCommand(auditorZoneListCmd, auditorZoneMPListCmd, auditorZoneReloadCmd, auditorZoneBumpCmd)

	auditorEventlogCmd.AddCommand(auditorEventlogListCmd, auditorEventlogClearCmd)
	AuditorCmd.AddCommand(auditorEventlogCmd, auditorObservationsCmd)
}
