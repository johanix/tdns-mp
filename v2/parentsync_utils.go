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
func queryParentKeyStateDetailed(hdb *HsyncDB, imr *Imr, keyName string, keyid uint16) (uint8, string, error) {
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

	sak, err := hdb.GetSig0Keys(keyName, tdns.Sig0StateActive)
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

// zonePublishesKey reports whether the zone's apex carries a KEY RRset: the
// zone has a SIG(0) key, whoever holds its private part.
func zonePublishesKey(zd *MPZoneData) bool {
	if zd == nil || zd.ZoneData == nil {
		return false
	}
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return false
	}
	rrset, ok := apex.RRtypes.Get(dns.TypeKEY)
	return ok && len(rrset.RRs) > 0
}

// mayGenerateZoneKey says whether a leader that holds no SIG(0) key for the
// zone, and was handed none by a peer, may make one.
//
// A leader that won the zone in an election may, as before. A leader that the
// zone arrived at, because the zone's set of providers changed, may only when
// the zone publishes no key. A zone that publishes one has a key that the
// parent holds, made by the leader the zone had. A new key in its place is
// not trusted by the parent, and its publication replaces the zone's KEY
// RRset, so the key the parent trusts is gone from the zone as well.
func mayGenerateZoneKey(elected bool, zd *MPZoneData) bool {
	return elected || !zonePublishesKey(zd)
}
