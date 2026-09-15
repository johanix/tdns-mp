/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * tdns-mpcli signer key: the key lifecycle of a zone tdns-mp runs (the
 * replacement commands of the key lifecycle ownership design, §5).
 */
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/ryanuber/columnize"
	"github.com/spf13/cobra"

	tdnsmp "github.com/johanix/tdns-mp/v2"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

func newSignerKeyCmd(kind string) *cobra.Command {
	c := &cobra.Command{
		Use:   "key",
		Short: "The key lifecycle of a zone tdns-mp runs",
		Long: `The keys of a multi-provider zone whose key lifecycle tdns-mp's state
machine runs (key-lifecycle-zones in the signer's config): what it holds,
what is on its way to the other signing providers, a rollover on request,
and the retry or withdrawal of a key another provider rejected. On such a
zone tdns's own rollover and policy commands refuse and name these.`,
	}
	rollover := &cobra.Command{
		Use:   "rollover",
		Short: "Promote the next standby key of a role on the next tick",
		Run: func(cmd *cobra.Command, args []string) {
			resp := signerKeyPost(cmd, tdnsmp.SignerKeyPost{Command: "rollover", Zone: signerKeyZone(cmd), Role: mustFlag(cmd, "role")})
			fmt.Println(resp.Msg)
		},
	}
	rollover.Flags().StringP("role", "r", "KSK", "KSK or ZSK")
	cancel := &cobra.Command{
		Use:   "cancel",
		Short: "Withdraw a rollover request not yet fired",
		Run: func(cmd *cobra.Command, args []string) {
			resp := signerKeyPost(cmd, tdnsmp.SignerKeyPost{Command: "rollover-cancel", Zone: signerKeyZone(cmd), Role: mustFlag(cmd, "role")})
			fmt.Println(resp.Msg)
		},
	}
	cancel.Flags().StringP("role", "r", "KSK", "KSK or ZSK")
	rollover.AddCommand(cancel)
	retry := &cobra.Command{
		Use:   "retry",
		Short: "Distribute a key (or its removal) again, a rejection forgotten",
		Run: func(cmd *cobra.Command, args []string) {
			resp := signerKeyPost(cmd, tdnsmp.SignerKeyPost{Command: "retry", Zone: signerKeyZone(cmd), KeyId: signerKeyId(cmd)})
			fmt.Println(resp.Msg)
		},
	}
	withdraw := &cobra.Command{
		Use:   "withdraw",
		Short: "Give a key up before it signs: its removal is distributed",
		Run: func(cmd *cobra.Command, args []string) {
			resp := signerKeyPost(cmd, tdnsmp.SignerKeyPost{Command: "withdraw", Zone: signerKeyZone(cmd), KeyId: signerKeyId(cmd)})
			fmt.Println(resp.Msg)
		},
	}
	for _, sub := range []*cobra.Command{retry, withdraw} {
		sub.Flags().Uint16P("keyid", "k", 0, "Key tag of the key")
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "The zone's keys, the distributions in flight and the rollovers requested",
		Run: func(cmd *cobra.Command, args []string) {
			resp := signerKeyPost(cmd, tdnsmp.SignerKeyPost{Command: "status", Zone: signerKeyZone(cmd)})
			printSignerKeyStatus(resp.Status)
		},
	}
	policy := &cobra.Command{
		Use:   "policy",
		Short: "The policy the state machine applies; --set binds another",
		Long: `Without --set, the owner's policy fields as the state machine applies them
(algorithms, lifetimes, standby counts, propagation delay, withdrawal
margin, resend interval). With --set NAME, binds tdns's DNSSEC policy NAME
to the zone on the owner's behalf: lifetimes, standby counts and margin
follow at once. A policy that changes the mode, an algorithm or the DS
model is refused: that is a rollover, not a binding.`,
		Run: func(cmd *cobra.Command, args []string) {
			if name := mustFlag(cmd, "set"); name != "" {
				resp := signerKeyPost(cmd, tdnsmp.SignerKeyPost{Command: "policy-set", Zone: signerKeyZone(cmd), Policy: name})
				fmt.Println(resp.Msg)
				return
			}
			resp := signerKeyPost(cmd, tdnsmp.SignerKeyPost{Command: "policy", Zone: signerKeyZone(cmd)})
			printSignerKeyPolicy(resp.Status)
		},
	}
	policy.Flags().String("set", "", "Name of the DNSSEC policy to bind")
	zones := &cobra.Command{
		Use:   "zones",
		Short: "The zones whose key lifecycle tdns-mp runs",
		Run: func(cmd *cobra.Command, args []string) {
			resp := signerKeyPost(cmd, tdnsmp.SignerKeyPost{Command: "zones"})
			if len(resp.Zones) == 0 {
				fmt.Println("tdns-mp's state machine runs no zone's key lifecycle")
				return
			}
			for _, z := range resp.Zones {
				fmt.Println(z)
			}
		},
	}
	for _, sub := range []*cobra.Command{rollover, cancel, retry, withdraw, status, policy} {
		sub.Flags().StringP("zone", "z", "", "Zone name")
	}
	c.AddCommand(status, zones, rollover, retry, withdraw, policy)
	return c
}

func mustFlag(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func signerKeyZone(cmd *cobra.Command) string {
	zone := mustFlag(cmd, "zone")
	if zone == "" {
		zone = tdns.Globals.Zonename
	}
	if zone == "" {
		log.Fatalf("Error: no zone given (--zone)")
	}
	return dns.Fqdn(zone)
}

func signerKeyId(cmd *cobra.Command) uint16 {
	id, _ := cmd.Flags().GetUint16("keyid")
	if id == 0 {
		log.Fatalf("Error: no key given (--keyid)")
	}
	return id
}

func signerKeyPost(cmd *cobra.Command, req tdnsmp.SignerKeyPost) tdnsmp.SignerKeyResponse {
	api, err := GetApiClientForCmd(cmd, true)
	if err != nil {
		log.Fatalf("Error getting API client: %v", err)
	}
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(req); err != nil {
		log.Fatalf("Error encoding request: %v", err)
	}
	_, body, err := api.Post("/signer/key", buf.Bytes())
	if err != nil {
		log.Fatalf("Error from API: %v", err)
	}
	var resp tdnsmp.SignerKeyResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Fatalf("Error decoding response: %v (%q)", err, string(body))
	}
	if resp.Error {
		log.Fatalf("Error: %s", resp.ErrorMsg)
	}
	return resp
}

func yn(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func ynp(b *bool) string {
	if b == nil {
		return "-"
	}
	return yn(*b)
}

func stampOf(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04")
}

func printSignerKeyStatus(st *tdnsmp.KeyLifecycleStatus) {
	if st == nil {
		fmt.Println("no status")
		return
	}
	others := strings.Join(st.OtherSigners, ", ")
	if others == "" {
		others = "none (alone: no confirmations awaited)"
	}
	fmt.Printf("Zone %s: policy %q; other signing providers: %s\n", st.Zone, st.PolicyName, others)
	rows := []string{"KeyID|Role|Alg|State|Pub|Sign|DS|Published|Active|Retired"}
	for _, k := range st.Keys {
		rows = append(rows, fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s|%s|%s", k.KeyId, k.Role, dns.AlgorithmToString[k.Algorithm], k.State,
			yn(k.Pub), yn(k.Sign), ynp(k.DS), stampOf(k.PublishedAt), stampOf(k.ActiveAt), stampOf(k.RetiredAt)))
	}
	for _, k := range st.Foreign {
		rows = append(rows, fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|-|-|-", k.KeyId, k.Role, dns.AlgorithmToString[k.Algorithm], k.State, yn(k.Pub), yn(k.Sign), ynp(k.DS)))
	}
	fmt.Println(columnize.SimpleFormat(rows))
	if len(st.InFlight) > 0 {
		fmt.Println("\nDistributions in flight:")
		rows = []string{"KeyID|Kind|Sent|Expected|Applied|Pending|Rejected|Reason"}
		for _, d := range st.InFlight {
			kind := "key"
			if d.Removal {
				kind = "removal"
			}
			rows = append(rows, fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s|%s", d.KeyId, kind, d.SentAt.UTC().Format("2006-01-02 15:04"),
				orDash(strings.Join(d.Expected, ",")), orDash(strings.Join(d.Applied, ",")), orDash(strings.Join(d.Pending, ",")), orDash(strings.Join(d.Rejected, ",")), orDash(d.Reason)))
		}
		fmt.Println(columnize.SimpleFormat(rows))
	}
	if len(st.Rollovers) > 0 {
		r := append([]string(nil), st.Rollovers...)
		sort.Strings(r)
		fmt.Printf("\nRollover requested: %s\n", strings.Join(r, ", "))
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func lifetimeOf(d time.Duration) string {
	if d == 0 {
		return "forever"
	}
	return d.String()
}

func printSignerKeyPolicy(st *tdnsmp.KeyLifecycleStatus) {
	if st == nil {
		fmt.Println("no policy")
		return
	}
	p := st.Policy
	rows := []string{
		fmt.Sprintf("Zone|%s", st.Zone),
		fmt.Sprintf("Policy|%s", st.PolicyName),
		fmt.Sprintf("KSK algorithm|%s", dns.AlgorithmToString[p.KSKAlgorithm]),
		fmt.Sprintf("ZSK algorithm|%s", dns.AlgorithmToString[p.ZSKAlgorithm]),
		fmt.Sprintf("KSK lifetime|%s", lifetimeOf(p.KSKLifetime)),
		fmt.Sprintf("ZSK lifetime|%s", lifetimeOf(p.ZSKLifetime)),
		fmt.Sprintf("Standby KSKs|%d", p.StandbyKSK),
		fmt.Sprintf("Standby ZSKs|%d", p.StandbyZSK),
		fmt.Sprintf("Propagation delay|%s", p.PropagationDelay),
		fmt.Sprintf("Withdrawal margin|%s", p.Margin),
		fmt.Sprintf("Resend after|%s", p.ResendAfter),
	}
	fmt.Println(columnize.SimpleFormat(rows))
}
