/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * CLI commands for DNS message router introspection.
 * Available under both "agent router" and "combiner router".
 * Each parent gets its own cobra.Command instance to avoid
 * dual-registration conflicts; the implementation functions
 * are shared.
 */

package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	tdns "github.com/johanix/tdns/v2"
	tdnscli "github.com/johanix/tdns/v2/cli"
	"github.com/spf13/cobra"
)

// --- Agent router commands ---

var agentRouterCmd = &cobra.Command{
	Use:   "router",
	Short: "DNS message router introspection commands",
}

var agentRouterListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered message handlers",
	Run:   func(cmd *cobra.Command, args []string) { runRouterList("agent", args) },
}

var agentRouterDescribeCmd = &cobra.Command{
	Use:   "describe",
	Short: "Show detailed router state",
	Run:   func(cmd *cobra.Command, args []string) { runRouterDescribe("agent", args) },
}

var agentRouterMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Show router metrics (use --detailed for per-peer breakdown)",
	Run:   func(cmd *cobra.Command, args []string) { runRouterMetrics("agent", args) },
}

var agentRouterWalkCmd = &cobra.Command{
	Use:   "walk",
	Short: "Walk all handlers with visitor pattern",
	Run:   func(cmd *cobra.Command, args []string) { runRouterWalk("agent", args) },
}

var agentRouterResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset router metrics",
	Run:   func(cmd *cobra.Command, args []string) { runRouterReset("agent", args) },
}

// --- Combiner router commands (same implementation, separate instances) ---

var combinerRouterCmd = &cobra.Command{
	Use:   "router",
	Short: "DNS message router introspection commands",
}

var combinerRouterListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered message handlers",
	Run:   func(cmd *cobra.Command, args []string) { runRouterList("combiner", args) },
}

var combinerRouterDescribeCmd = &cobra.Command{
	Use:   "describe",
	Short: "Show detailed router state",
	Run:   func(cmd *cobra.Command, args []string) { runRouterDescribe("combiner", args) },
}

var combinerRouterMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Show router metrics (use --detailed for per-peer breakdown)",
	Run:   func(cmd *cobra.Command, args []string) { runRouterMetrics("combiner", args) },
}

var combinerRouterWalkCmd = &cobra.Command{
	Use:   "walk",
	Short: "Walk all handlers with visitor pattern",
	Run:   func(cmd *cobra.Command, args []string) { runRouterWalk("combiner", args) },
}

var combinerRouterResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset router metrics",
	Run:   func(cmd *cobra.Command, args []string) { runRouterReset("combiner", args) },
}

// --- Signer router commands ---

var signerRouterCmd = &cobra.Command{
	Use:   "router",
	Short: "DNS message router introspection commands",
}

var signerRouterMetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Show router metrics",
	Run:   func(cmd *cobra.Command, args []string) { runRouterMetrics("signer", args) },
}

// --- Shared implementation functions ---

func runRouterList(parent string, args []string) {
	api, err := tdnscli.GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	req := tdns.AgentMgmtPost{
		Command: "router-list",
	}

	_, buf, err := api.RequestNG("POST", "/agent", req, true)
	if err != nil {
		log.Fatalf("API request failed: %v", err)
	}

	var amr tdns.AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if amr.Error {
		log.Fatalf("API error: %s", amr.ErrorMsg)
	}

	if amr.Data == nil {
		fmt.Println("No router data available")
		return
	}

	routerData, ok := amr.Data.(map[string]interface{})
	if !ok {
		log.Fatalf("Unexpected response format")
	}

	handlers, ok := routerData["handlers"].(map[string]interface{})
	if !ok {
		fmt.Println("No handlers registered")
		return
	}

	fmt.Println("DNS Message Router - Registered Handlers")
	fmt.Println("=========================================")
	fmt.Println()

	for msgType, handlerList := range handlers {
		handlerSlice, ok := handlerList.([]interface{})
		if !ok {
			continue
		}

		fmt.Printf("%s (%d handlers):\n", msgType, len(handlerSlice))
		for i, h := range handlerSlice {
			handler, ok := h.(map[string]interface{})
			if !ok {
				continue
			}

			name := handler["name"].(string)
			priority := int(handler["priority"].(float64))
			callCount := int(handler["call_count"].(float64))
			errorCount := int(handler["error_count"].(float64))

			fmt.Printf("  %d. %s (priority=%d)\n", i+1, name, priority)
			fmt.Printf("     Calls: %d, Errors: %d\n", callCount, errorCount)

			if desc, ok := handler["description"].(string); ok && desc != "" {
				fmt.Printf("     Description: %s\n", desc)
			}
		}
		fmt.Println()
	}
}

func runRouterDescribe(parent string, args []string) {
	api, err := tdnscli.GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	req := tdns.AgentMgmtPost{
		Command: "router-describe",
	}

	_, buf, err := api.RequestNG("POST", "/agent", req, true)
	if err != nil {
		log.Fatalf("API request failed: %v", err)
	}

	var amr tdns.AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if amr.Error {
		log.Fatalf("API error: %s", amr.ErrorMsg)
	}

	if description, ok := amr.Data.(string); ok {
		fmt.Println(description)
	} else {
		fmt.Println("No router description available")
	}
}

var routerMetricsDetailed bool

func runRouterMetrics(parent string, args []string) {
	api, err := tdnscli.GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	// Determine endpoint and request format based on parent
	var metrics map[string]interface{}

	switch parent {
	case "agent":
		req := tdns.AgentMgmtPost{
			Command: "router-metrics",
		}
		if routerMetricsDetailed {
			req.Data = map[string]interface{}{
				"detailed": true,
			}
		}
		_, buf, err := api.RequestNG("POST", "/agent", req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}
		var amr tdns.AgentMgmtResponse
		if err := json.Unmarshal(buf, &amr); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}
		if amr.Error {
			log.Fatalf("API error: %s", amr.ErrorMsg)
		}
		if amr.Data == nil {
			fmt.Println("No metrics available")
			return
		}
		var ok bool
		metrics, ok = amr.Data.(map[string]interface{})
		if !ok {
			log.Fatalf("Unexpected metrics format")
		}

	case "combiner", "signer":
		endpoint := "/" + parent
		if parent == "combiner" {
			endpoint = "/combiner/mp"
		}
		req := tdns.CombinerDebugPost{
			Command: "router-metrics",
		}
		if routerMetricsDetailed {
			req.Data = map[string]interface{}{
				"detailed": true,
			}
		}
		_, buf, err := api.RequestNG("POST", endpoint, req, true)
		if err != nil {
			log.Fatalf("API request failed: %v", err)
		}
		var resp tdns.CombinerDebugResponse
		if err := json.Unmarshal(buf, &resp); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}
		if resp.Error {
			log.Fatalf("API error: %s", resp.ErrorMsg)
		}
		if resp.Data == nil {
			fmt.Println("No metrics available")
			return
		}
		var ok bool
		metrics, ok = resp.Data.(map[string]interface{})
		if !ok {
			log.Fatalf("Unexpected metrics format")
		}

	default:
		log.Fatalf("Unknown parent: %s", parent)
	}

	header := fmt.Sprintf("DNS Message Router - Metrics (%s)", parent)
	printMetricsBlock(header, metrics)

	if unhandled, ok := metrics["unhandled_types"].(map[string]interface{}); ok && len(unhandled) > 0 {
		fmt.Println("\nUnhandled Message Types:")
		for msgType, count := range unhandled {
			fmt.Printf("  %-20s %d\n", msgType, int(count.(float64)))
		}
	}

	// Per-peer detailed breakdown (agent only)
	if routerMetricsDetailed {
		peers, ok := metrics["peers"].([]interface{})
		if !ok || len(peers) == 0 {
			fmt.Println("\nNo per-peer data available.")
			return
		}

		for _, p := range peers {
			peer, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			peerID := peer["peer_id"].(string)
			state := peer["state"].(string)
			fmt.Printf("\nPeer: %s (%s)\n", peerID, state)
			fmt.Println(strings.Repeat("-", 40+len(peerID)))
			printMetricsBlock("", peer)
		}
	}
}

func printMetricsBlock(header string, m map[string]interface{}) {
	if header != "" {
		fmt.Println(header)
		fmt.Println(strings.Repeat("=", len(header)))
		fmt.Println()
	}

	totalSent := toInt(m["total_sent"])
	totalRecv := toInt(m["total_received"])
	fmt.Printf("Total Messages:      %d  (sent: %d, received: %d)\n", totalSent+totalRecv, totalSent, totalRecv)

	fmt.Println()
	fmt.Printf("%-20s %8s %8s\n", "Message Type", "Sent", "Received")
	fmt.Printf("%-20s %8s %8s\n", strings.Repeat("-", 20), strings.Repeat("-", 8), strings.Repeat("-", 8))
	fmt.Printf("%-20s %8d %8d\n", "hello", toInt(m["hello_sent"]), toInt(m["hello_received"]))
	fmt.Printf("%-20s %8d %8d\n", "beat", toInt(m["beat_sent"]), toInt(m["beat_received"]))
	fmt.Printf("%-20s %8d %8d\n", "sync/update", toInt(m["sync_sent"]), toInt(m["sync_received"]))
	fmt.Printf("%-20s %8d %8d\n", "ping", toInt(m["ping_sent"]), toInt(m["ping_received"]))
	fmt.Printf("%-20s %8d %8d\n", "confirm", toInt(m["confirm_sent"]), toInt(m["confirm_received"]))
	otherSent := toInt(m["other_sent"])
	otherRecv := toInt(m["other_received"])
	if otherSent+otherRecv > 0 {
		fmt.Printf("%-20s %8d %8d\n", "other", otherSent, otherRecv)
	}

	// Only print error counters for the aggregate block (they exist there, not per-peer)
	if _, ok := m["handler_errors"]; ok {
		fmt.Println()
		fmt.Printf("Handler Errors:      %d\n", toInt(m["handler_errors"]))
		fmt.Printf("Middleware Errors:    %d\n", toInt(m["middleware_errors"]))
		fmt.Printf("Unknown Messages:    %d\n", toInt(m["unknown_messages"]))
	}
}

func toInt(v interface{}) int {
	if v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case uint64:
		return int(n)
	default:
		return 0
	}
}

func runRouterWalk(parent string, args []string) {
	api, err := tdnscli.GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	req := tdns.AgentMgmtPost{
		Command: "router-walk",
	}

	_, buf, err := api.RequestNG("POST", "/agent", req, true)
	if err != nil {
		log.Fatalf("API request failed: %v", err)
	}

	var amr tdns.AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if amr.Error {
		log.Fatalf("API error: %s", amr.ErrorMsg)
	}

	if amr.Data == nil {
		fmt.Println("No handlers found")
		return
	}

	walkResults, ok := amr.Data.([]interface{})
	if !ok {
		log.Fatalf("Unexpected walk results format")
	}

	fmt.Println("DNS Message Router - Handler Walk")
	fmt.Println("==================================")
	fmt.Println()

	for i, item := range walkResults {
		handler, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		msgType := handler["message_type"].(string)
		name := handler["name"].(string)
		priority := int(handler["priority"].(float64))
		registered := handler["registered"].(string)

		fmt.Printf("%d. [%s] %s\n", i+1, msgType, name)
		fmt.Printf("   Priority: %d, Registered: %s\n", priority, registered)

		if desc, ok := handler["description"].(string); ok && desc != "" {
			fmt.Printf("   Description: %s\n", desc)
		}
		fmt.Println()
	}

	fmt.Printf("Total handlers: %d\n", len(walkResults))
}

func runRouterReset(parent string, args []string) {
	api, err := tdnscli.GetApiClient(parent, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}

	fmt.Print("This will reset all router metrics. Continue? [y/N]: ")
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))

	if response != "y" && response != "yes" {
		fmt.Println("Cancelled.")
		os.Exit(0)
	}

	req := tdns.AgentMgmtPost{
		Command: "router-reset",
	}

	_, buf, err := api.RequestNG("POST", "/agent", req, true)
	if err != nil {
		log.Fatalf("API request failed: %v", err)
	}

	var amr tdns.AgentMgmtResponse
	if err := json.Unmarshal(buf, &amr); err != nil {
		log.Fatalf("Failed to parse response: %v", err)
	}

	if amr.Error {
		log.Fatalf("API error: %s", amr.ErrorMsg)
	}

	fmt.Println("Router metrics reset successfully.")
}

func init() {
	// Agent gets its own router command tree
	AgentCmd.AddCommand(agentRouterCmd)
	agentRouterCmd.AddCommand(agentRouterListCmd)
	agentRouterCmd.AddCommand(agentRouterDescribeCmd)
	agentRouterCmd.AddCommand(agentRouterMetricsCmd)
	agentRouterCmd.AddCommand(agentRouterWalkCmd)
	agentRouterCmd.AddCommand(agentRouterResetCmd)

	agentRouterMetricsCmd.Flags().BoolVar(&routerMetricsDetailed, "detailed", false, "Show per-peer breakdown")

	// Combiner gets its own router command tree (separate instances)
	CombinerCmd.AddCommand(combinerRouterCmd)
	combinerRouterCmd.AddCommand(combinerRouterListCmd)
	combinerRouterCmd.AddCommand(combinerRouterDescribeCmd)
	combinerRouterCmd.AddCommand(combinerRouterMetricsCmd)
	combinerRouterCmd.AddCommand(combinerRouterWalkCmd)
	combinerRouterCmd.AddCommand(combinerRouterResetCmd)

	combinerRouterMetricsCmd.Flags().BoolVar(&routerMetricsDetailed, "detailed", false, "Show per-peer breakdown")

	// Signer gets only the metrics command
	SignerCmd.AddCommand(signerRouterCmd)
	signerRouterCmd.AddCommand(signerRouterMetricsCmd)

	signerRouterMetricsCmd.Flags().BoolVar(&routerMetricsDetailed, "detailed", false, "Show per-peer breakdown")
}
