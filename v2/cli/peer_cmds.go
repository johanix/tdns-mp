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

func runPeerApiPing(role, peerID string) {
	if peerID == "" {
		log.Fatalf("--id flag is required")
	}

	resp, err := SendPeerCommand(role, tdnsmp.PeerPost{
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
func runPeerReset(role, peerID string) {
	switch role {
	case "agent", "auditor":
		// proceed
	default:
		fmt.Fprintf(os.Stderr, "peer reset is not applicable to %s (static peer configuration)\n", role)
		return
	}

	if peerID == "" {
		log.Fatalf("--id flag is required")
	}

	resp, err := SendPeerCommand(role, tdnsmp.PeerPost{
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
func addPeerLeaves(parent *cobra.Command, role string) {
	var pingID, apiPingID, resetID string

	pingCmd := &cobra.Command{
		Use:   "ping",
		Short: "Ping a peer via DNS CHUNK",
		Long: `Send a DNS CHUNK ping to a peer and report the result.
The --id flag specifies the peer identity (e.g. agent.beta.dnslab.
or combiner.dnslab.).`,
		Run: func(cmd *cobra.Command, args []string) { runPeerPing(role, pingID) },
	}
	pingCmd.Flags().StringVar(&pingID, "id", "", "Peer identity to ping (required)")

	apiPingCmd := &cobra.Command{
		Use:   "apiping",
		Short: "Ping a peer via HTTPS API",
		Run:   func(cmd *cobra.Command, args []string) { runPeerApiPing(role, apiPingID) },
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
		Run: func(cmd *cobra.Command, args []string) { runPeerReset(role, resetID) },
	}
	resetCmd.Flags().StringVar(&resetID, "id", "", "Peer identity to reset (required)")

	parent.AddCommand(pingCmd)
	parent.AddCommand(apiPingCmd)
	parent.AddCommand(resetCmd)
}

// NewPeerCmd returns a fresh `peer` subtree (parent + the three
// leaves) bound to role. Use when the role does not already own
// a `peer` parent elsewhere (e.g. signer, auditor). For roles
// whose `peer` parent has extra children defined in another file
// (agent, combiner), call addPeerLeaves on that existing parent
// instead.
func NewPeerCmd(role string) *cobra.Command {
	peerCmd := &cobra.Command{
		Use:   "peer",
		Short: "Peer management commands",
	}
	addPeerLeaves(peerCmd, role)
	return peerCmd
}

func init() {
	// Agent and combiner peer parents are defined in
	// agent_cmds.go and combiner_peer_cmds.go respectively
	// (they have additional list/zones/zone/resync children
	// from those files). Just attach the role-uniform leaves
	// here.
	addPeerLeaves(agentPeerCmd, "agent")
	addPeerLeaves(combinerPeerCmd, "combiner")

	// Signer has no peer parent elsewhere; build and attach the
	// whole subtree here.
	SignerCmd.AddCommand(NewPeerCmd("signer"))
}
