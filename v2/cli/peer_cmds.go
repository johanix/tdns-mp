/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * CLI commands for the /peer endpoint.
 * Three commands (ping, apiping, reset) available under all MP
 * roles. peer-reset is gated at worker entry to non-agent roles
 * because it depends on IMR-based dynamic discovery that signer
 * and combiner don't do. ping/apiping work on every role.
 *
 * The role-uniform cobra shells live here; the existing
 * combinerPeerCmd parent (in combiner_peer_cmds.go) and the
 * agentPeerCmd parent (in agent_cmds.go) are reused. signerPeerCmd
 * is created here — it didn't exist before Task N.
 */

package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	tdns "github.com/johanix/tdns/v2"
	tdnscli "github.com/johanix/tdns/v2/cli"
	"github.com/spf13/cobra"
)

// SendPeerCommand posts a PeerPost to the /peer endpoint of the
// role-selected API client and returns the parsed response.
func SendPeerCommand(role string, req tdnsmp.PeerPost) (*tdnsmp.PeerResponse, error) {
	api, err := tdnscli.GetApiClient(role, true)
	if err != nil {
		return nil, fmt.Errorf("error getting API client: %v", err)
	}

	_, buf, err := api.RequestNG("POST", "/peer", req, true)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}

	var resp tdnsmp.PeerResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &resp, nil
}

// --- Workers ---

func runPeerPing(role, peerID string) {
	if peerID == "" {
		log.Fatalf("--id flag is required")
	}

	resp, err := SendPeerCommand(role, tdnsmp.PeerPost{
		Command: "peer-ping",
		PeerID:  tdns.AgentId(peerID),
	})
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	if resp.Error {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.ErrorMsg)
		os.Exit(1)
	}
	fmt.Println(resp.Msg)
}

func runPeerApiPing(role, peerID string) {
	if peerID == "" {
		log.Fatalf("--id flag is required")
	}

	resp, err := SendPeerCommand(role, tdnsmp.PeerPost{
		Command: "peer-apiping",
		PeerID:  tdns.AgentId(peerID),
	})
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	if resp.Error {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.ErrorMsg)
		os.Exit(1)
	}
	fmt.Println(resp.Msg)
}

// runPeerReset gates non-agent roles with an "not applicable"
// message because peer-reset depends on IMR-based dynamic
// discovery — signer and combiner use static peer configuration.
func runPeerReset(role, peerID string) {
	if role != "agent" {
		fmt.Fprintf(os.Stderr, "peer reset is not applicable to %s (static peer configuration)\n", role)
		return
	}

	if peerID == "" {
		log.Fatalf("--id flag is required")
	}

	resp, err := SendPeerCommand(role, tdnsmp.PeerPost{
		Command: "peer-reset",
		PeerID:  tdns.AgentId(peerID),
	})
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	if resp.Error {
		fmt.Fprintf(os.Stderr, "Error: %s\n", resp.ErrorMsg)
		os.Exit(1)
	}
	fmt.Println(resp.Msg)
}

// --- Cobra shells (3 roles × 3 commands = 9) ---

var (
	peerPingID    string
	peerApiPingID string
	peerResetID   string

	agentPeerPingCmd = &cobra.Command{
		Use:   "ping",
		Short: "Ping a peer via DNS CHUNK",
		Long: `Send a DNS CHUNK ping to a peer and report the result.
The --id flag specifies the peer identity (e.g. agent.beta.dnslab.
or combiner.dnslab.).`,
		Run: func(cmd *cobra.Command, args []string) { runPeerPing("agent", peerPingID) },
	}
	agentPeerApiPingCmd = &cobra.Command{
		Use:   "apiping",
		Short: "Ping a peer via HTTPS API",
		Run:   func(cmd *cobra.Command, args []string) { runPeerApiPing("agent", peerApiPingID) },
	}
	agentPeerResetCmd = &cobra.Command{
		Use:   "reset",
		Short: "Reset peer to NEEDED state, flush cache, restart discovery",
		Long: `Reset a peer agent to initial NEEDED state. Flushes all IMR
cache entries for the peer's discovery names and restarts
discovery from scratch. Use this when a peer is stuck in UNKNOWN
or KNOWN state.`,
		Run: func(cmd *cobra.Command, args []string) { runPeerReset("agent", peerResetID) },
	}

	combinerPeerPingCmd = &cobra.Command{
		Use:   "ping",
		Short: "Ping a peer via DNS CHUNK",
		Run:   func(cmd *cobra.Command, args []string) { runPeerPing("combiner", peerPingID) },
	}
	combinerPeerApiPingCmd = &cobra.Command{
		Use:   "apiping",
		Short: "Ping a peer via HTTPS API",
		Run:   func(cmd *cobra.Command, args []string) { runPeerApiPing("combiner", peerApiPingID) },
	}
	combinerPeerResetCmd = &cobra.Command{
		Use:   "reset",
		Short: "Reset peer (not applicable to combiner — prints a notice)",
		Run:   func(cmd *cobra.Command, args []string) { runPeerReset("combiner", peerResetID) },
	}

	signerPeerCmd = &cobra.Command{
		Use:   "peer",
		Short: "Peer management commands",
	}
	signerPeerPingCmd = &cobra.Command{
		Use:   "ping",
		Short: "Ping a peer via DNS CHUNK",
		Run:   func(cmd *cobra.Command, args []string) { runPeerPing("signer", peerPingID) },
	}
	signerPeerApiPingCmd = &cobra.Command{
		Use:   "apiping",
		Short: "Ping a peer via HTTPS API",
		Run:   func(cmd *cobra.Command, args []string) { runPeerApiPing("signer", peerApiPingID) },
	}
	signerPeerResetCmd = &cobra.Command{
		Use:   "reset",
		Short: "Reset peer (not applicable to signer — prints a notice)",
		Run:   func(cmd *cobra.Command, args []string) { runPeerReset("signer", peerResetID) },
	}
)

func init() {
	// Agent tree — parent agentPeerCmd is defined in agent_cmds.go.
	agentPeerCmd.AddCommand(agentPeerPingCmd)
	agentPeerCmd.AddCommand(agentPeerApiPingCmd)
	agentPeerCmd.AddCommand(agentPeerResetCmd)
	agentPeerPingCmd.Flags().StringVar(&peerPingID, "id", "", "Peer identity to ping (required)")
	agentPeerApiPingCmd.Flags().StringVar(&peerApiPingID, "id", "", "Peer identity to ping (required)")
	agentPeerResetCmd.Flags().StringVar(&peerResetID, "id", "", "Peer identity to reset (required)")

	// Combiner tree — parent combinerPeerCmd is defined in combiner_peer_cmds.go.
	combinerPeerCmd.AddCommand(combinerPeerPingCmd)
	combinerPeerCmd.AddCommand(combinerPeerApiPingCmd)
	combinerPeerCmd.AddCommand(combinerPeerResetCmd)
	combinerPeerPingCmd.Flags().StringVar(&peerPingID, "id", "", "Peer identity to ping (required)")
	combinerPeerApiPingCmd.Flags().StringVar(&peerApiPingID, "id", "", "Peer identity to ping (required)")
	combinerPeerResetCmd.Flags().StringVar(&peerResetID, "id", "", "Peer identity to reset (not used for combiner)")

	// Signer tree — signerPeerCmd parent created here (didn't exist before Task N).
	SignerCmd.AddCommand(signerPeerCmd)
	signerPeerCmd.AddCommand(signerPeerPingCmd)
	signerPeerCmd.AddCommand(signerPeerApiPingCmd)
	signerPeerCmd.AddCommand(signerPeerResetCmd)
	signerPeerPingCmd.Flags().StringVar(&peerPingID, "id", "", "Peer identity to ping (required)")
	signerPeerApiPingCmd.Flags().StringVar(&peerApiPingID, "id", "", "Peer identity to ping (required)")
	signerPeerResetCmd.Flags().StringVar(&peerResetID, "id", "", "Peer identity to reset (not used for signer)")
}
