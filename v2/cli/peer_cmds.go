/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * CLI commands for the /peer endpoint.
 * Three commands (ping, apiping, reset) available under all MP
 * roles. peer-reset is gated at worker entry to non-agent roles
 * because it depends on IMR-based dynamic discovery that signer
 * and combiner don't do. ping/apiping work on every role.
 *
 * The kind-uniform cobra shells live here; the combiner and agent
 * peer parents (combiner_peer_cmds.go, agent_cmds.go) add these leaves
 * to their own subtrees; signer and auditor take the whole subtree.
 */

package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	"github.com/spf13/cobra"
)

// SendPeerCommand posts a PeerPost to the /peer endpoint of the instance
// cmd's tree targets and returns the parsed response.
func SendPeerCommand(cmd *cobra.Command, req tdnsmp.PeerPost) (*tdnsmp.PeerResponse, error) {
	api, err := GetApiClientForCmd(cmd, true)
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

func runPeerPing(cmd *cobra.Command, peerID string) {
	if peerID == "" {
		log.Fatalf("--id flag is required")
	}

	resp, err := SendPeerCommand(cmd, tdnsmp.PeerPost{
		Command: "peer-ping",
		PeerID:  AgentId(peerID),
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

func runPeerApiPing(cmd *cobra.Command, peerID string) {
	if peerID == "" {
		log.Fatalf("--id flag is required")
	}

	resp, err := SendPeerCommand(cmd, tdnsmp.PeerPost{
		Command: "peer-apiping",
		PeerID:  AgentId(peerID),
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

// runPeerReset gates roles that don't have an AgentRegistry (and
// thus no dynamic discovery to reset) with a "not applicable"
// message. Agents and auditors both use HSYNC3-driven dynamic
// discovery and support reset; signer and combiner use static
// peer configuration and don't.
func runPeerReset(cmd *cobra.Command, kind, peerID string) {
	switch kind {
	case "agent", "auditor":
		// proceed
	default:
		fmt.Fprintf(os.Stderr, "peer reset is not applicable to %s (static peer configuration)\n", kind)
		return
	}

	if peerID == "" {
		log.Fatalf("--id flag is required")
	}

	resp, err := SendPeerCommand(cmd, tdnsmp.PeerPost{
		Command: "peer-reset",
		PeerID:  AgentId(peerID),
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

// addPeerLeaves attaches the three role-uniform peer leaves
// (ping, apiping, reset) to parent. Each leaf binds the --id flag
// to its own local string so flags don't bleed between roles.
// Reset's help text is honest about which roles actually act on
// it; the runPeerReset gate prints "not applicable" when invoked
// on a static-peer role.
func addPeerLeaves(parent *cobra.Command, kind string) {
	var pingID, apiPingID, resetID string

	pingCmd := &cobra.Command{
		Use:   "ping",
		Short: "Ping a peer via DNS CHUNK",
		Long: `Send a DNS CHUNK ping to a peer and report the result.
The --id flag specifies the peer identity (e.g. agent.beta.dnslab.
or combiner.dnslab.).`,
		Run: func(cmd *cobra.Command, args []string) { runPeerPing(cmd, pingID) },
	}
	pingCmd.Flags().StringVar(&pingID, "id", "", "Peer identity to ping (required)")

	apiPingCmd := &cobra.Command{
		Use:   "apiping",
		Short: "Ping a peer via HTTPS API",
		Run:   func(cmd *cobra.Command, args []string) { runPeerApiPing(cmd, apiPingID) },
	}
	apiPingCmd.Flags().StringVar(&apiPingID, "id", "", "Peer identity to ping (required)")

	resetCmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset peer (agent/auditor only; no-op elsewhere)",
		Long: `Reset a peer to initial NEEDED state. Flushes all IMR
cache entries for the peer's discovery names and restarts
discovery from scratch. Use this when a peer is stuck in UNKNOWN
or KNOWN state. Only applicable to roles that use dynamic
HSYNC3-driven discovery (agent, auditor); a no-op on
static-peer roles (signer, combiner).`,
		Run: func(cmd *cobra.Command, args []string) { runPeerReset(cmd, kind, resetID) },
	}
	resetCmd.Flags().StringVar(&resetID, "id", "", "Peer identity to reset (required)")

	parent.AddCommand(pingCmd)
	parent.AddCommand(apiPingCmd)
	parent.AddCommand(resetCmd)
}

// NewPeerCmd returns a fresh `peer` subtree (parent + the three
// leaves) for a daemon of the given kind. Use when the kind does not
// already own a `peer` parent elsewhere (signer, auditor). For kinds
// whose `peer` parent has extra children defined in another file
// (agent, combiner), the parent's factory calls addPeerLeaves.
func NewPeerCmd(kind string) *cobra.Command {
	peerCmd := &cobra.Command{
		Use:   "peer",
		Short: "Peer management commands",
	}
	addPeerLeaves(peerCmd, kind)
	return peerCmd
}
