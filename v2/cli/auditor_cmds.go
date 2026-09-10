/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Auditor CLI commands. Phase C scope: eventlog list/clear, zones,
 * observations subcommands. All call POST /api/v1/auditor on the
 * auditor with a JSON body whose Command field selects the action.
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// newAuditorZoneMPListCmd is the auditor-specific "mplist" subcommand,
// handed to tdnscli.NewZoneCmd as an extra by NewAuditorTree.
func newAuditorZoneMPListCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "mplist",
		Short: "List multi-provider zones with HSYNCPARAM details",
		Run:   func(cmd *cobra.Command, args []string) { runZoneMPList(cmd, args) },
	}
	return c
}

func newAuditorEventlogCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "eventlog",
		Short: "Audit event log commands",
	}
	c.AddCommand(newAuditorEventlogListCmd(kind), newAuditorEventlogClearCmd(kind))
	return c
}

func newAuditorEventlogListCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "list",
		Short: "List audit events",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			req := AuditPost{Command: "eventlog-list"}
			if zone, _ := cmd.Flags().GetString("zone"); zone != "" {
				req.Zone = dns.Fqdn(zone)
			}
			if since, _ := cmd.Flags().GetString("since"); since != "" {
				req.Since = since
			}
			limit, _ := cmd.Flags().GetInt("last")
			if limit > 0 {
				req.Limit = limit
			} else {
				req.Limit = 50
			}
			resp, err := callAuditor(cmd, req)
			if err != nil {
				log.Fatal(err)
			}
			if len(resp.Events) == 0 {
				fmt.Println("No events found")
				return
			}
			printEvents(resp.Events)
		},
	}
	c.Flags().StringP("zone", "z", "", "filter by zone")
	c.Flags().String("since", "", "events since (RFC3339)")
	c.Flags().Int("last", 50, "number of events to show")
	return c
}

func newAuditorEventlogClearCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "clear",
		Short: "Clear audit events",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			req := AuditPost{Command: "eventlog-clear"}
			if zone, _ := cmd.Flags().GetString("zone"); zone != "" {
				req.Zone = dns.Fqdn(zone)
			}
			if olderThan, _ := cmd.Flags().GetString("older-than"); olderThan != "" {
				req.OlderThan = olderThan
			}
			req.All, _ = cmd.Flags().GetBool("all")
			if !req.All && req.Zone == "" && req.OlderThan == "" {
				log.Fatal("must specify --zone, --older-than, or --all")
			}
			resp, err := callAuditor(cmd, req)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(resp.Msg)
		},
	}
	c.Flags().StringP("zone", "z", "", "clear events for zone")
	c.Flags().String("older-than", "", "clear events older than duration (e.g. 24h)")
	c.Flags().Bool("all", false, "clear all events")
	return c
}

func newAuditorZonesCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "zones",
		Short: "List audited zones with provider summaries",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			resp, err := callAuditor(cmd, AuditPost{Command: "zones"})
			if err != nil {
				log.Fatal(err)
			}
			if len(resp.Zones) == 0 {
				fmt.Println("No zones tracked")
				return
			}
			printZones(resp.Zones)
		},
	}
	return c
}

func newAuditorObservationsCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "observations",
		Short: "Show anomalies/observations detected by the auditor",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			req := AuditPost{Command: "observations"}
			if zone, _ := cmd.Flags().GetString("zone"); zone != "" {
				req.Zone = dns.Fqdn(zone)
			}
			resp, err := callAuditor(cmd, req)
			if err != nil {
				log.Fatal(err)
			}
			if len(resp.Observations) == 0 {
				fmt.Println("No observations")
				return
			}
			printObservations(resp.Observations)
		},
	}
	c.Flags().StringP("zone", "z", "", "filter by zone")
	return c
}

func callAuditor(cmd *cobra.Command, req AuditPost) (*AuditResponse, error) {
	api, err := GetApiClientForCmd(cmd, true)
	if err != nil {
		return nil, fmt.Errorf("error getting API client: %w", err)
	}
	_, buf, err := api.RequestNG("POST", "/auditor", req, true)
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

func printEvents(events []AuditEvent) {
	fmt.Printf("%-20s  %-10s  %-25s  %-25s  %s\n",
		"Time", "Type", "Zone", "Originator", "Summary")
	fmt.Printf("%-20s  %-10s  %-25s  %-25s  %s\n",
		strings.Repeat("-", 20), strings.Repeat("-", 10),
		strings.Repeat("-", 25), strings.Repeat("-", 25),
		strings.Repeat("-", 40))
	for _, e := range events {
		fmt.Printf("%-20s  %-10s  %-25s  %-25s  %s\n",
			e.Time.Format("2006-01-02 15:04:05"),
			e.EventType, e.Zone, e.Originator, e.Summary)
	}
}

func printZones(zones []AuditZoneSummary) {
	for _, z := range zones {
		fmt.Printf("Zone: %s  (%d providers, serial %d)\n",
			z.Zone, z.ProviderCount, z.ZoneSerial)
		if len(z.Providers) == 0 {
			continue
		}
		fmt.Printf("  %-30s  %-8s  %-12s  %-12s  %s\n",
			"Provider", "Signer", "Last BEAT", "Last SYNC", "Gossip")
		for _, p := range z.Providers {
			fmt.Printf("  %-30s  %-8t  %-12s  %-12s  %s\n",
				p.Identity, p.IsSigner,
				ageOrDash(p.LastBeat),
				ageOrDash(p.LastSync),
				p.GossipState)
		}
	}
}

func printObservations(obs []AuditObservation) {
	fmt.Printf("%-20s  %-8s  %-25s  %-30s  %s\n",
		"Time", "Severity", "Zone", "Provider", "Message")
	for _, o := range obs {
		fmt.Printf("%-20s  %-8s  %-25s  %-30s  %s\n",
			o.Time.Format("2006-01-02 15:04:05"),
			o.Severity, o.Zone, o.Provider, o.Message)
	}
}

func ageOrDash(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return time.Since(t).Round(time.Second).String()
}
