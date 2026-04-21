/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Configurator: live-server gate.
 *
 * Before rewriting a server's config, probe its API using the
 * *existing* credentials (the new apikey is not yet accepted by
 * the running server). A responsive server requires a typed
 * confirmation string per role, e.g. `yes, reconfigure mpagent`.
 *
 * Refusing any gate aborts the entire write. The configurator
 * does not support "partial apply" of coordinated configs —
 * missing a single server's update would leave the system with
 * mismatched apikeys/identities across roles.
 */
package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	tdns "github.com/johanix/tdns/v2"
)

// liveProbe is the per-role input the gate needs. It is drawn
// from the *existing* parsed config, not the new values.
type liveProbe struct {
	role      string // "mpagent" | "mpsigner" | "mpcombiner"
	baseURL   string // https://host:port/api/v1
	apiKey    string
	hasConfig bool // false when no existing config file was present
}

func liveProbesFrom(current CoordinatedValues, existing map[string]string) []liveProbe {
	ip := current.Global.PublicIP
	return []liveProbe{
		{
			role:      "mpagent",
			baseURL:   baseURL(ip, agentApiPort),
			apiKey:    current.Agent.ApiKey,
			hasConfig: existing[pathMpagent] != "",
		},
		{
			role:      "mpsigner",
			baseURL:   baseURL(ip, signerApiPort),
			apiKey:    current.Signer.ApiKey,
			hasConfig: existing[pathMpsigner] != "",
		},
		{
			role:      "mpcombiner",
			baseURL:   baseURL(ip, combinerApiPort),
			apiKey:    current.Combiner.ApiKey,
			hasConfig: existing[pathMpcombiner] != "",
		},
	}
}

func baseURL(ip string, port int) string {
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("https://%s:%d/api/v1", ip, port)
}

// isAlive returns true if the API at p.baseURL accepts a ping
// signed with p.apiKey. All errors (connection refused, timeout,
// auth failure) are treated as "not alive" — the caller doesn't
// care *why*, only whether to gate.
func (p liveProbe) isAlive() bool {
	if !p.hasConfig || p.baseURL == "" || p.apiKey == "" {
		return false
	}
	c := tdns.NewClient(p.role, p.baseURL, p.apiKey, "X-API-Key", "insecure")
	if c == nil {
		return false
	}
	_, err := c.SendPing(1, false)
	return err == nil
}

// gateLiveServers probes each role whose config is about to
// change and, for every live one, requires a typed confirmation.
// Returns nil iff the gate is cleared (all live servers
// confirmed, or none live). A non-nil error means the user
// refused or input was interrupted — abort the write.
func gateLiveServers(
	w io.Writer,
	in *bufio.Reader,
	current CoordinatedValues,
	existing map[string]string,
	changes []fileChange,
) error {
	changing := make(map[string]bool, len(changes))
	for _, c := range changes {
		if c.changed() {
			changing[c.path] = true
		}
	}

	roleToPath := map[string]string{
		"mpagent":    pathMpagent,
		"mpsigner":   pathMpsigner,
		"mpcombiner": pathMpcombiner,
	}

	fmt.Fprintln(w, "\nProbing live servers…")
	var live []liveProbe
	for _, p := range liveProbesFrom(current, existing) {
		if !changing[roleToPath[p.role]] {
			continue
		}
		if p.isAlive() {
			fmt.Fprintf(w, "  %s: LIVE (existing config responds to ping)\n", p.role)
			live = append(live, p)
		} else {
			fmt.Fprintf(w, "  %s: quiet\n", p.role)
		}
	}

	if len(live) == 0 {
		return nil
	}

	fmt.Fprintln(w, "\nOne or more target servers are currently running.")
	fmt.Fprintln(w, "Rewriting their configs will not affect the running")
	fmt.Fprintln(w, "daemon until it is restarted, but a mismatched apikey")
	fmt.Fprintln(w, "or identity can surprise operators who restart later.")
	fmt.Fprintln(w, "Confirm each live server explicitly.")

	for _, p := range live {
		want := "yes, reconfigure " + p.role
		fmt.Fprintf(w, "\n  type exactly '%s' to proceed: ", want)
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("aborted: input closed during live-server gate")
		}
		if strings.TrimRight(line, "\r\n") != want {
			return fmt.Errorf("aborted: confirmation string mismatch for %s", p.role)
		}
	}
	return nil
}
