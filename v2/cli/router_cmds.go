/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * CLI commands for DNS message router introspection.
 * Available under all MP roles (agent, combiner, signer).
 * Each role gets its own cobra.Command instances (cobra
 * disallows sharing); all of them funnel through the shared
 * runRouterXxx(role, args) workers which POST to /router.
 */

package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	tdnscli "github.com/johanix/tdns/v2/cli"
	"github.com/spf13/cobra"
)

// SendRouterCommand posts a RouterPost to the /router endpoint of
// the role-selected API client and returns the parsed response.
func SendRouterCommand(role string, req tdnsmp.RouterPost) (*tdnsmp.RouterResponse, error) {
	api, err := tdnscli.GetApiClient(role, true)
	if err != nil {
		return nil, fmt.Errorf("error getting API client: %v", err)
	}

	_, buf, err := api.RequestNG("POST", "/router", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}

	var resp tdnsmp.RouterResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &resp, nil
}

// --- Shared implementation functions ---

func runRouterList(role string, args []string) {
	resp, err := SendRouterCommand(role, tdnsmp.RouterPost{
		Command: "router-list",
	})
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	if resp.Error {
		log.Fatalf("API error: %s", resp.ErrorMsg)
	}

	if resp.Data == nil {
		fmt.Println("No router data available")
		return
	}

	routerData, ok := resp.Data.(map[string]interface{})
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

			name, ok := handler["name"].(string)
			if !ok {
				continue
			}
			priorityF, ok := handler["priority"].(float64)
			if !ok {
				continue
			}
			priority := int(priorityF)
			callCountF, ok := handler["call_count"].(float64)
			if !ok {
				continue
			}
			callCount := int(callCountF)
			errorCountF, ok := handler["error_count"].(float64)
			if !ok {
				continue
			}
			errorCount := int(errorCountF)

			fmt.Printf("  %d. %s (priority=%d)\n", i+1, name, priority)
			fmt.Printf("     Calls: %d, Errors: %d\n", callCount, errorCount)

			if desc, ok := handler["description"].(string); ok && desc != "" {
				fmt.Printf("     Description: %s\n", desc)
			}
		}
		fmt.Println()
	}
}

func runRouterDescribe(role string, args []string) {
	resp, err := SendRouterCommand(role, tdnsmp.RouterPost{
		Command: "router-describe",
	})
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	if resp.Error {
		log.Fatalf("API error: %s", resp.ErrorMsg)
	}

	if description, ok := resp.Data.(string); ok {
		fmt.Println(description)
	} else {
		fmt.Println("No router description available")
	}
}

var routerMetricsDetailed bool

func runRouterMetrics(role string, args []string) {
	resp, err := SendRouterCommand(role, tdnsmp.RouterPost{
		Command:  "router-metrics",
		Detailed: routerMetricsDetailed,
	})
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	if resp.Error {
		log.Fatalf("API error: %s", resp.ErrorMsg)
	}
	if resp.Data == nil {
		fmt.Println("No metrics available")
		return
	}

	metrics, ok := resp.Data.(map[string]interface{})
	if !ok {
		log.Fatalf("Unexpected metrics format")
	}

	header := fmt.Sprintf("DNS Message Router - Metrics (%s)", role)
	printMetricsBlock(header, metrics)

	if unhandled, ok := metrics["unhandled_types"].(map[string]interface{}); ok && len(unhandled) > 0 {
		fmt.Println("\nUnhandled Message Types:")
		for msgType, count := range unhandled {
			fmt.Printf("  %-20s %d\n", msgType, int(count.(float64)))
		}
	}

	// Per-peer detailed breakdown
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

	// Only print error counters for the aggregate block
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

func runRouterWalk(role string, args []string) {
	resp, err := SendRouterCommand(role, tdnsmp.RouterPost{
		Command: "router-walk",
	})
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	if resp.Error {
		log.Fatalf("API error: %s", resp.ErrorMsg)
	}

	if resp.Data == nil {
		fmt.Println("No handlers found")
		return
	}

	walkResults, ok := resp.Data.([]interface{})
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

		msgType, ok := handler["message_type"].(string)
		if !ok {
			continue
		}
		name, ok := handler["name"].(string)
		if !ok {
			continue
		}
		priorityF, ok := handler["priority"].(float64)
		if !ok {
			continue
		}
		priority := int(priorityF)
		registered, ok := handler["registered"].(string)
		if !ok {
			continue
		}

		fmt.Printf("%d. [%s] %s\n", i+1, msgType, name)
		fmt.Printf("   Priority: %d, Registered: %s\n", priority, registered)

		if desc, ok := handler["description"].(string); ok && desc != "" {
			fmt.Printf("   Description: %s\n", desc)
		}
		fmt.Println()
	}

	fmt.Printf("Total handlers: %d\n", len(walkResults))
}

func runRouterReset(role string, args []string) {
	fmt.Print("This will reset all router metrics. Continue? [y/N]: ")
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))

	if response != "y" && response != "yes" {
		fmt.Println("Cancelled.")
		os.Exit(0)
	}

	resp, err := SendRouterCommand(role, tdnsmp.RouterPost{
		Command: "router-reset",
	})
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	if resp.Error {
		log.Fatalf("API error: %s", resp.ErrorMsg)
	}

	fmt.Println("Router metrics reset successfully.")
}

// --- Cobra shells (3 roles × 5 commands = 15) ---

var (
	agentRouterCmd = &cobra.Command{
		Use:   "router",
		Short: "DNS message router introspection commands",
	}
	agentRouterListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all registered message handlers",
		Run:   func(cmd *cobra.Command, args []string) { runRouterList("agent", args) },
	}
	agentRouterDescribeCmd = &cobra.Command{
		Use:   "describe",
		Short: "Show detailed router state",
		Run:   func(cmd *cobra.Command, args []string) { runRouterDescribe("agent", args) },
	}
	agentRouterMetricsCmd = &cobra.Command{
		Use:   "metrics",
		Short: "Show router metrics (use --detailed for per-peer breakdown)",
		Run:   func(cmd *cobra.Command, args []string) { runRouterMetrics("agent", args) },
	}
	agentRouterWalkCmd = &cobra.Command{
		Use:   "walk",
		Short: "Walk all handlers with visitor pattern",
		Run:   func(cmd *cobra.Command, args []string) { runRouterWalk("agent", args) },
	}
	agentRouterResetCmd = &cobra.Command{
		Use:   "reset",
		Short: "Reset router metrics",
		Run:   func(cmd *cobra.Command, args []string) { runRouterReset("agent", args) },
	}

	combinerRouterCmd = &cobra.Command{
		Use:   "router",
		Short: "DNS message router introspection commands",
	}
	combinerRouterListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all registered message handlers",
		Run:   func(cmd *cobra.Command, args []string) { runRouterList("combiner", args) },
	}
	combinerRouterDescribeCmd = &cobra.Command{
		Use:   "describe",
		Short: "Show detailed router state",
		Run:   func(cmd *cobra.Command, args []string) { runRouterDescribe("combiner", args) },
	}
	combinerRouterMetricsCmd = &cobra.Command{
		Use:   "metrics",
		Short: "Show router metrics (use --detailed for per-peer breakdown)",
		Run:   func(cmd *cobra.Command, args []string) { runRouterMetrics("combiner", args) },
	}
	combinerRouterWalkCmd = &cobra.Command{
		Use:   "walk",
		Short: "Walk all handlers with visitor pattern",
		Run:   func(cmd *cobra.Command, args []string) { runRouterWalk("combiner", args) },
	}
	combinerRouterResetCmd = &cobra.Command{
		Use:   "reset",
		Short: "Reset router metrics",
		Run:   func(cmd *cobra.Command, args []string) { runRouterReset("combiner", args) },
	}

	signerRouterCmd = &cobra.Command{
		Use:   "router",
		Short: "DNS message router introspection commands",
	}
	signerRouterListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all registered message handlers",
		Run:   func(cmd *cobra.Command, args []string) { runRouterList("signer", args) },
	}
	signerRouterDescribeCmd = &cobra.Command{
		Use:   "describe",
		Short: "Show detailed router state",
		Run:   func(cmd *cobra.Command, args []string) { runRouterDescribe("signer", args) },
	}
	signerRouterMetricsCmd = &cobra.Command{
		Use:   "metrics",
		Short: "Show router metrics (use --detailed for per-peer breakdown)",
		Run:   func(cmd *cobra.Command, args []string) { runRouterMetrics("signer", args) },
	}
	signerRouterWalkCmd = &cobra.Command{
		Use:   "walk",
		Short: "Walk all handlers with visitor pattern",
		Run:   func(cmd *cobra.Command, args []string) { runRouterWalk("signer", args) },
	}
	signerRouterResetCmd = &cobra.Command{
		Use:   "reset",
		Short: "Reset router metrics",
		Run:   func(cmd *cobra.Command, args []string) { runRouterReset("signer", args) },
	}
)

func init() {
	// Agent tree
	AgentCmd.AddCommand(agentRouterCmd)
	agentRouterCmd.AddCommand(agentRouterListCmd)
	agentRouterCmd.AddCommand(agentRouterDescribeCmd)
	agentRouterCmd.AddCommand(agentRouterMetricsCmd)
	agentRouterCmd.AddCommand(agentRouterWalkCmd)
	agentRouterCmd.AddCommand(agentRouterResetCmd)
	agentRouterMetricsCmd.Flags().BoolVar(&routerMetricsDetailed, "detailed", false, "Show per-peer breakdown")

	// Combiner tree
	CombinerCmd.AddCommand(combinerRouterCmd)
	combinerRouterCmd.AddCommand(combinerRouterListCmd)
	combinerRouterCmd.AddCommand(combinerRouterDescribeCmd)
	combinerRouterCmd.AddCommand(combinerRouterMetricsCmd)
	combinerRouterCmd.AddCommand(combinerRouterWalkCmd)
	combinerRouterCmd.AddCommand(combinerRouterResetCmd)
	combinerRouterMetricsCmd.Flags().BoolVar(&routerMetricsDetailed, "detailed", false, "Show per-peer breakdown")

	// Signer tree
	SignerCmd.AddCommand(signerRouterCmd)
	signerRouterCmd.AddCommand(signerRouterListCmd)
	signerRouterCmd.AddCommand(signerRouterDescribeCmd)
	signerRouterCmd.AddCommand(signerRouterMetricsCmd)
	signerRouterCmd.AddCommand(signerRouterWalkCmd)
	signerRouterCmd.AddCommand(signerRouterResetCmd)
	signerRouterMetricsCmd.Flags().BoolVar(&routerMetricsDetailed, "detailed", false, "Show per-peer breakdown")
}
