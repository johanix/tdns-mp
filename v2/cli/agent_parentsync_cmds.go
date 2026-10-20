/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * CLI commands for the agent's parentsync-* management commands: who leads
 * a zone's delegation sync towards the parent, and where the parent stands
 * on the SIG(0) key that signs it. They go through the agent's leader
 * election manager and answer about this agent's role among the zone's
 * providers.
 */
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	tdns "github.com/johanix/tdns/v2"
	tdnscli "github.com/johanix/tdns/v2/cli"
	"github.com/spf13/cobra"
)

func newAgentParentSyncCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "parentsync",
		Short: "Delegation sync leader, election and SIG(0) key bootstrap for a zone",
		Long: `Commands for this agent's part in a zone's delegation sync with the parent:
which agent leads it among the zone's providers, and where the parent stands
on the SIG(0) key that signs the UPDATEs. All take the zone with --zone.`,
	}
	c.AddCommand(newAgentParentSyncStatusCmd(kind), newAgentParentSyncElectionCmd(kind),
		newAgentParentSyncInquireCmd(kind), newAgentParentSyncBootstrapCmd(kind))
	// A refusal from the agent comes back from the leaf as an error. The
	// caller of Execute prints it, once, and it is no reason to print the
	// usage.
	for _, leaf := range c.Commands() {
		leaf.SilenceErrors = true
		leaf.SilenceUsage = true
	}
	return c
}

func newAgentParentSyncStatusCmd(kind string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the leader, the SIG(0) key and the parent's sync schemes for a zone",
		Long: `Show where this agent stands in a zone's delegation sync with the parent:
the leader among the zone's providers and its lease, the zone's active SIG(0)
key and where its KEY record is published, the sync schemes the parent
advertises in DSYNC, and the state of the zone's peers.

The agent looks up the parent's DSYNC records and the published KEY records
through its own resolver when asked, so the answer can take a few seconds.

The parent state of the key is the one the agent last recorded, not a new
inquiry (see "inquire").

Example:
  tdns-mpcli agent parentsync status --zone example.com.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			amr, err := sendAgentParentSyncCmd(cmd, "parentsync-status")
			if err != nil {
				return err
			}
			status, err := parentSyncStatusFromResponse(amr)
			if err != nil {
				return err
			}
			printParentSyncStatus(cmd.OutOrStdout(), status)
			return nil
		},
	}
}

func newAgentParentSyncElectionCmd(kind string) *cobra.Command {
	return &cobra.Command{
		Use:   "election",
		Short: "Start a leader election for the zone's provider group",
		Long: `Start a leader election now. The agents elect by themselves, when a provider
group has become operational and again before the leader's lease runs out;
this command is for a group that has no leader and does not get one.

A zone in a provider group gets a group election, and its leader leads every
zone of the group, not only the one named here. The election is started
whatever the state of the group:
  - A leader with a valid lease stays the leader until the new election is
    decided. The winner may be another agent.
  - An election that is running is not waited for: a new one is started.
  - Every voting member has to answer. While one does not, the election is
    aborted after five seconds and started again, until all have answered.
The agent that wins does what every new leader does, for each zone of the
group that syncs with its parent through the agents. For a parent that takes
UPDATEs it publishes the zone's SIG(0) key, generating one when no agent has
it, and bootstraps the key with the parent. And it brings the delegation in
sync.

Refused: a zone the agent does not know, and a group with no voting members.
An agent that is not a voting member of the group starts nothing, and says so.

A zone that no provider group covers gets an election of its own. That one is
refused unless every configured peer for the zone is operational; with no
peers the agent becomes the leader at once.

The command returns when the election is started, not when it is decided.
"parentsync status" and "gossip state" show the outcome.

Example:
  tdns-mpcli agent parentsync election --zone example.com.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			amr, err := sendAgentParentSyncCmd(cmd, "parentsync-election")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), amr.Msg)
			return nil
		},
	}
}

func newAgentParentSyncInquireCmd(kind string) *cobra.Command {
	return &cobra.Command{
		Use:   "inquire",
		Short: "Ask the parent for the state of the zone's SIG(0) key",
		Long: `Send a KeyState inquiry about the zone's active SIG(0) key to the parent's
UPDATE receiver, found through the parent's DSYNC records, and print the state
the parent reports for the key.

The agent need not be the leader. The inquiry is signed with the key.

The parent's answer is authenticated before it is read, and the line printed
says whether it was. An answer whose signature is wrong is a failure and is
not printed. An answer that cannot be authenticated, because it is unsigned
or because the key it is signed with has no chain of trust, is a failure too,
unless the agent is configured with parentsync.update.allow-insecure: then it
is printed and marked as not authenticated.

The answer is not recorded, so the parent state in "parentsync status" does
not change.

Fails when the agent has no active SIG(0) key for the zone, when the parent
advertises no UPDATE scheme, and when the receiver does not answer.

Example:
  tdns-mpcli agent parentsync inquire --zone example.com.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			amr, err := sendAgentParentSyncCmd(cmd, "parentsync-inquire")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), amr.Msg)
			return nil
		},
	}
}

func newAgentParentSyncBootstrapCmd(kind string) *cobra.Command {
	return &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstrap the zone's SIG(0) key with the parent (leader only)",
		Long: `Have the agent bring the parent to trust the zone's active SIG(0) key. This
is what a new leader does by itself after its election; the command runs it
again.

Refused unless this agent is the zone's delegation sync leader, and when it
has no active SIG(0) key for the zone.

The command returns at once and the work runs in the agent:
  - The agent asks the parent for the state of the key.
  - A parent that already trusts the key is sent no bootstrap. The agent then
    checks that the delegation is in sync.
  - A parent that does not know the key is sent the bootstrap UPDATE, and is
    asked again until it trusts the key or the attempts run out.
  - A parent that requires a manual bootstrap is left to its operator.
Nothing is done, and nothing is reported here, for a zone whose HSYNCPARAM
does not say parentsync="agent", and while an earlier run for the same key is
still asking the parent.

The outcome is in the agent's log, and in the parent state that
"parentsync status" shows for the key.

Example:
  tdns-mpcli agent parentsync bootstrap --zone example.com.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			amr, err := sendAgentParentSyncCmd(cmd, "parentsync-bootstrap")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), amr.Msg)
			return nil
		},
	}
}

// sendAgentParentSyncCmd posts one of the agent's parentsync-* commands for
// the zone given with --zone. An answer that reports an error is returned as
// an error, so a leaf has one way to fail.
func sendAgentParentSyncCmd(cmd *cobra.Command, command string) (*AgentMgmtResponse, error) {
	tdnscli.PrepArgs("zonename")

	amr, err := SendAgentMgmtCmd(cmd, &AgentMgmtPost{
		Command: command,
		Zone:    ZoneName(tdns.Globals.Zonename),
	})
	if err != nil {
		return nil, err
	}
	if amr.Error {
		return nil, fmt.Errorf("from agent %q: %s", amr.Identity, amr.ErrorMsg)
	}
	return amr, nil
}

// parentSyncStatusFromResponse reads the status that parentsync-status puts
// in the response's data. It arrives as untyped JSON, so it goes through the
// encoder once more to land in the agent's own type.
func parentSyncStatusFromResponse(amr *AgentMgmtResponse) (tdnsmp.ParentSyncStatus, error) {
	var status tdnsmp.ParentSyncStatus
	if amr.Data == nil {
		return status, fmt.Errorf("the agent's answer carries no parent sync status")
	}
	buf, err := json.Marshal(amr.Data)
	if err != nil {
		return status, fmt.Errorf("failed to read the parent sync status: %v", err)
	}
	if err := json.Unmarshal(buf, &status); err != nil {
		return status, fmt.Errorf("failed to parse the parent sync status: %v", err)
	}
	return status, nil
}

// printParentSyncStatus prints the agent's parent sync status for a zone.
// Every string in it is printed through termSafe. The identities, names and
// records come from the zone's peers, the zone and the parent's DNS. The rest
// are the agent's own names for a code or a state. They are escaped too: this
// prints what a daemon sent, and does not check it against the agent's code.
func printParentSyncStatus(w io.Writer, s tdnsmp.ParentSyncStatus) {
	fmt.Fprintf(w, "Parent sync status for zone %s\n", termSafe(string(s.Zone)))
	fmt.Fprintf(w, "  checked:        %s\n", s.LastChecked.Format("2006-01-02 15:04:05 MST"))

	// The lease is counted from the moment the agent made this report, on
	// the agent's clock: the clock here need not agree with it.
	lease := s.LeaderExpiry.Sub(s.LastChecked).Truncate(time.Second)
	leader := termSafe(string(s.Leader))
	switch {
	case s.Leader == "":
		fmt.Fprintln(w, "  leader:         none")
	case lease <= 0:
		fmt.Fprintf(w, "  leader:         none (the lease of %s has expired)\n", leader)
	case s.IsLeader:
		fmt.Fprintf(w, "  leader:         %s (this agent), lease expires in %s\n", leader, lease)
	default:
		fmt.Fprintf(w, "  leader:         %s, lease expires in %s\n", leader, lease)
	}
	fmt.Fprintf(w, "  election term:  %d\n", s.ElectionTerm)
	if c := s.CatchUp; c != nil {
		if c.NotVoting {
			fmt.Fprintln(w, "  catch-up:       none: this agent does not vote in the zone, and asks nothing")
		} else if c.CaughtUp {
			fmt.Fprintln(w, "  catch-up:       caught up")
		} else {
			fmt.Fprintf(w, "  catch-up:       not caught up, waiting for %s\n", termSafe(c.WaitingFor))
		}
	}
	if s.ParentSync != "" {
		fmt.Fprintf(w, "  parent sync:    %s\n", termSafe(s.ParentSync))
	}
	if s.KeyHold != "" {
		fmt.Fprintf(w, "  parent sync:    %s\n", termSafe(s.KeyHold))
	}
	if s.DSSet != "" {
		fmt.Fprintf(w, "  DS set:         %s\n", termSafe(s.DSSet))
	}

	if s.KeyAlgorithm == "" {
		fmt.Fprintln(w, "  SIG(0) key:     none active for the zone")
	} else {
		fmt.Fprintf(w, "  SIG(0) key:     %s, key id %d\n", termSafe(s.KeyAlgorithm), s.KeyID)
		fmt.Fprintf(w, "  KEY record:     %s\n", termSafe(strings.Join(strings.Fields(s.KeyRR), " ")))
		// 0 is what the keystore holds for a key the parent was never asked
		// about, and it is also a KeyState code of its own. The report does
		// not tell the two apart, so this line cannot either.
		if s.ParentState == 0 {
			fmt.Fprintf(w, "  parent state:   0 (not asked yet, or the parent answered %q)\n", s.ParentStateName)
		} else {
			fmt.Fprintf(w, "  parent state:   %s (%d), as last recorded\n", termSafe(s.ParentStateName), s.ParentState)
		}
	}
	fmt.Fprintf(w, "  KEY at apex:    %s\n", publishedOrNot(s.ApexPublished))
	fmt.Fprintf(w, "  CDS at apex:    %s\n", publishedOrNot(s.CdsPublished))
	fmt.Fprintf(w, "  CSYNC at apex:  %s\n", publishedOrNot(s.CsyncPublished))
	if s.ZoneSigned {
		fmt.Fprintln(w, "  zone:           signed")
	} else {
		fmt.Fprintln(w, "  zone:           not signed")
	}

	if s.ParentZone == "" {
		fmt.Fprintln(w, "  parent zone:    unknown (the agent's DSYNC lookup found nothing)")
	} else {
		fmt.Fprintf(w, "  parent zone:    %s\n", termSafe(s.ParentZone))
		if s.ActiveScheme == "" {
			fmt.Fprintln(w, "  scheme in use:  none (the parent advertises none of the agent's schemes)")
		} else {
			fmt.Fprintf(w, "  scheme in use:  %s\n", termSafe(s.ActiveScheme))
		}
	}

	if len(s.SyncSchemes) > 0 {
		fmt.Fprintln(w, "\nSync schemes the parent advertises:")
		fmt.Fprintf(w, "  %-8s  %-6s  %-5s  %s\n", "Scheme", "Type", "Port", "Target")
		for _, d := range s.SyncSchemes {
			fmt.Fprintf(w, "  %-8s  %-6s  %-5d  %s\n", termSafe(d.Scheme), termSafe(d.Type), d.Port, termSafe(d.Target))
		}
	}

	if len(s.ChildNS) > 0 {
		fmt.Fprintln(w, "\nNameservers of the zone:")
		for _, ns := range s.ChildNS {
			fmt.Fprintf(w, "  %s\n", termSafe(ns))
		}
	}

	if len(s.KeyPublication) > 0 {
		owners := make([]string, 0, len(s.KeyPublication))
		for owner := range s.KeyPublication {
			owners = append(owners, owner)
		}
		sort.Strings(owners)
		fmt.Fprintln(w, "\nKEY record under the nameservers:")
		for _, owner := range owners {
			fmt.Fprintf(w, "  %s  %s\n", termSafe(owner), publishedOrNot(s.KeyPublication[owner]))
		}
	}

	if c := s.CatchUp; c != nil && len(c.Peers) > 0 {
		fmt.Fprintln(w, "\nCatch-up, per voting member:")
		fmt.Fprintf(w, "  %-12s  %-8s  %-8s  %-10s  %s\n", "Answer", "Asked", "Answered", "Reason", "Identity")
		for _, p := range c.Peers {
			reason := p.Reason
			if reason == "" {
				reason = "-"
			}
			note := ""
			if p.Note != "" {
				note = "  (" + termSafe(p.Note) + ")"
			}
			fmt.Fprintf(w, "  %-12s  %-8s  %-8s  %-10s  %s%s\n", termSafe(p.Answer), clockOrDash(p.Asked), clockOrDash(p.Answered),
				termSafe(reason), termSafe(string(p.Identity)), note)
		}
	}

	if len(s.Peers) > 0 {
		// Transport is the one that is live towards the peer, "-" for none.
		fmt.Fprintln(w, "\nPeers:")
		fmt.Fprintf(w, "  %-12s  %-9s  %-11s  %s\n", "State", "Transport", "Operational", "Identity")
		for _, p := range s.Peers {
			operational := "no"
			if p.Operational {
				operational = "yes"
			}
			fmt.Fprintf(w, "  %-12s  %-9s  %-11s  %s\n",
				termSafe(p.State), termSafe(p.Transport), operational, termSafe(string(p.Identity)))
		}
	}
}

// clockOrDash is the time of day the agent gave, "-" for none.
func clockOrDash(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("15:04:05")
}

func publishedOrNot(published bool) string {
	if published {
		return "published"
	}
	return "not published"
}
