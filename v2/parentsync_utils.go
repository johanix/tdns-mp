/*
 * Parent sync utility functions copied from tdns/v2/parentsync_bootstrap.go.
 * These are local copies because the originals are unexported in tdns.
 */
package tdnsmp

import (
	"context"
	"fmt"
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// queryParentKeyStateDetailed sends a KeyState EDNS(0) inquiry to the parent
// and returns the parent's reported state for the key, including extra text.
func queryParentKeyStateDetailed(kdb *tdns.KeyDB, imr *tdns.Imr, keyName string, keyid uint16) (uint8, string, error) {
	ctx := context.Background()

	dsyncTarget, err := imr.LookupDSYNCTarget(ctx, keyName, dns.TypeANY, core.SchemeUpdate)
	if err != nil {
		return 0, "", fmt.Errorf("DSYNC lookup failed: %v", err)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(keyName), dns.TypeANY)

	edns0.AttachKeyStateToResponse(m, &edns0.KeyStateOption{
		KeyID:    keyid,
		KeyState: edns0.KeyStateInquiryKey,
	})

	sak, err := kdb.GetSig0Keys(keyName, tdns.Sig0StateActive)
	if err != nil || len(sak.Keys) == 0 {
		return 0, "", fmt.Errorf("no active SIG(0) key for %s", keyName)
	}

	signedMsg, err := tdns.SignMsg(*m, keyName, sak)
	if err != nil {
		return 0, "", fmt.Errorf("failed to sign KeyState inquiry: %v", err)
	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	if len(dsyncTarget.Addresses) == 0 {
		return 0, "", fmt.Errorf("DSYNC target has no addresses for %s", keyName)
	}

	r, _, err := c.Exchange(signedMsg, dsyncTarget.Addresses[0])
	if err != nil {
		return 0, "", fmt.Errorf("DNS exchange failed: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return 0, "", fmt.Errorf("DNS request failed with rcode %s", dns.RcodeToString[r.Rcode])
	}

	opt := r.IsEdns0()
	if opt == nil {
		return 0, "", fmt.Errorf("no EDNS(0) OPT RR in response")
	}

	keystate, found := edns0.ExtractKeyStateOption(opt)
	if !found {
		return 0, "", fmt.Errorf("KeyState option missing in response")
	}

	return keystate.KeyState, keystate.ExtraText, nil
}
