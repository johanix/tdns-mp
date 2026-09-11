/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * CLI commands for the /gossip endpoint.
 * Consolidated from the old agent-only agent_gossip_cmds.go; now
 * exposed under all MP roles (agent/combiner/signer/auditor).
 */
package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// SendGossipCommand posts a GossipPost to the /gossip endpoint of the
// instance cmd's tree targets and returns the parsed response.
func SendGossipCommand(cmd *cobra.Command, req tdnsmp.GossipPost) (*tdnsmp.GossipResponse, error) {
	api, err := GetApiClientForCmd(cmd, true)
	if err != nil {
		return nil, fmt.Errorf("error getting API client: %v", err)
	}

	_, buf, err := api.RequestNG("POST", "/gossip", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}

	var resp tdnsmp.GossipResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &resp, nil
}

// gossipRoleGuard prints "not applicable" to stderr for roles
// that don't participate in gossip (static-peer roles like signer
// and combiner) and returns true if the caller should bail out
// without making an RPC call. Agents and auditors do participate
// — both use HSYNC3-driven dynamic discovery.
func gossipRoleGuard(kind string) bool {
	switch kind {
	case "agent", "auditor":
		return false
	}
	fmt.Fprintf(os.Stderr, "%s does not participate in gossip (static peer configuration)\n", kind)
	return true
}

func runGossipZoneState(cmd *cobra.Command, kind, zone string) {
	if gossipRoleGuard(kind) {
		return
	}

	if zone == "" {
		log.Fatal("--zone flag is required")
	}
	zone = dns.Fqdn(zone)

	resp, err := SendGossipCommand(cmd, tdnsmp.GossipPost{
		Command: "gossip-zone-state",
		Zone:    zone,
	})
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	if resp.Error {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.ErrorMsg)
		os.Exit(1)
	}

	data, ok := resp.Data.(map[string]interface{})
	if !ok {
		fmt.Println("No data received")
		return
	}

	zoneStr, _ := data["zone"].(string)
	fmt.Printf("Zone: %s\n", zoneStr)

	if el, ok := data["election"].(map[string]interface{}); ok {
		status, _ := el["status"].(string)
		switch status {
		case "active":
			leader, _ := el["leader"].(string)
			term, _ := el["term"].(float64)
			expiresIn, _ := el["expires_in"].(string)
			fmt.Printf("Leader: %s (term %d, expires in %s)\n", leader, int(term), expiresIn)
		case "no_election":
			fmt.Println("Leader: no election held")
		case "invalidated":
			term, _ := el["term"].(float64)
			fmt.Printf("Leader: election invalidated (group degraded, last term %d)\n", int(term))
		case "expired":
			leader, _ := el["leader"].(string)
			term, _ := el["term"].(float64)
			fmt.Printf("Leader: expired (was %s, term %d)\n", leader, int(term))
		}
	}
	fmt.Println()

	var members []string
	if mlist, ok := data["members"].([]interface{}); ok {
		for _, m := range mlist {
			if s, ok := m.(string); ok {
				members = append(members, s)
			}
		}
	}

	if len(members) == 0 {
		fmt.Println("No members found")
		return
	}

	shortNames := shortenMemberNames(members)

	colWidth := 14
	for _, sn := range shortNames {
		if len(sn)+2 > colWidth {
			colWidth = len(sn) + 2
		}
	}

	fmt.Printf("%-20s", "REPORTER / PEER")
	for _, m := range members {
		fmt.Printf("%-*s", colWidth, shortNames[m])
	}
	fmt.Printf("%-6s\n", "AGE")

	matrix, _ := data["matrix"].([]interface{})
	for _, row := range matrix {
		r, ok := row.(map[string]interface{})
		if !ok {
			continue
		}
		reporter, _ := r["reporter"].(string)
		age, _ := r["age"].(string)
		peerStates, _ := r["peer_states"].(map[string]interface{})
		beatInterval := 0
		if v, ok := r["beat_interval"].(float64); ok {
			beatInterval = int(v)
		}

		fmt.Printf("%-20s", shortNames[reporter])
		for _, m := range members {
			if m == reporter {
				fmt.Printf("%-*s", colWidth, "—")
			} else if state, ok := peerStates[m].(string); ok {
				fmt.Printf("%-*s", colWidth, state)
			} else {
				fmt.Printf("%-*s", colWidth, "?")
			}
		}
		if beatInterval > 0 {
			fmt.Printf("%-6s  (%ds beats)\n", age, beatInterval)
		} else {
			fmt.Printf("%-6s\n", age)
		}
	}
}

// shortenMemberNames returns a map from full identity to a display
// form with the longest label-aligned common suffix removed.
func shortenMemberNames(members []string) map[string]string {
	out := make(map[string]string, len(members))
	if len(members) == 0 {
		return out
	}

	labelLists := make([][]string, len(members))
	for i, m := range members {
		labelLists[i] = strings.Split(strings.TrimSuffix(m, "."), ".")
	}

	shortest := len(labelLists[0])
	for _, ll := range labelLists[1:] {
		if len(ll) < shortest {
			shortest = len(ll)
		}
	}
	commonTail := 0
	for commonTail < shortest {
		ref := labelLists[0][len(labelLists[0])-1-commonTail]
		same := true
		for _, ll := range labelLists[1:] {
			if ll[len(ll)-1-commonTail] != ref {
				same = false
				break
			}
		}
		if !same {
			break
		}
		commonTail++
	}

	for i, m := range members {
		labels := labelLists[i]
		keep := len(labels) - commonTail
		if keep <= 0 {
			out[m] = m
			continue
		}
		out[m] = strings.Join(labels[:keep], ".")
	}
	return out
}

// NewGossipCmd returns a fresh `gossip` subtree for a daemon of the
// given kind. Each call returns a new set of *cobra.Command pointers,
// so callers can attach the same logical subcommand under multiple
// parents (one per tree) without sharing cobra-internal state. The
// target instance is read from the tree.
func NewGossipCmd(kind string) *cobra.Command {
	var zoneName string

	gossipCmd := &cobra.Command{
		Use:   "gossip",
		Short: "Gossip protocol commands",
	}
	stateCmd := &cobra.Command{
		Use:   "state",
		Short: "Show gossip state matrix for a zone",
		Long: `Display the N×N state matrix for the provider group serving a zone.
Each row is a reporting peer; each column shows that reporter's
view of another peer's state. A healthy group shows OPERATIONAL
in every non-diagonal cell.`,
		Run: func(cmd *cobra.Command, args []string) { runGossipZoneState(cmd, kind, zoneName) },
	}
	// Shorthand -z, matching the root's persistent --zone/-z which this
	// local flag shadows by name; without it "gossip state -z" failed with
	// "unknown shorthand flag" while every other zone command took -z.
	stateCmd.Flags().StringVarP(&zoneName, "zone", "z", "", "Zone name (required)")

	gossipCmd.AddCommand(stateCmd)
	return gossipCmd
}
