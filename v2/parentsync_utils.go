/*
 * The agent's KeyState inquiry to a zone's parent, for the operator's
 * `parentsync inquire`.
 */
package tdnsmp

import (
	"context"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/edns0"
)

// parentKeyStateInquiryTimeout bounds one inquiry: the DSYNC lookup, the
// exchange with each address of the parent's UPDATE receiver, and the
// lookups that authenticate its answer.
const parentKeyStateInquiryTimeout = 20 * time.Second

// queryParentKeyStateDetailed asks the parent what it holds about the zone's
// SIG(0) key keyid, and returns the state, the parent's extra text, and
// whether the answer was authenticated.
//
// An answer whose signature is wrong is an error, always. An answer that
// cannot be authenticated (unsigned, or signed with a key that has no chain
// of trust) is an error too, unless parentsync.update.allow-insecure is set:
// then it is returned with authenticated false, and the caller says so.
//
// It is tdns's own inquiry (QueryParentKeyState): a SIG(0)-signed QTYPE=KEY
// query with the KeyState option, over TCP, whose answer is authenticated
// before it is read. A copy of an earlier tdns inquiry used to live here. It
// asked with QTYPE=ANY, over UDP, and read the answer unauthenticated; a tdns
// parent answers only the QTYPE=KEY inquiry with the option, so every inquiry
// ended in "KeyState option missing in response".
//
// The inquiry ends with ctx, the request it is made for, or after
// parentKeyStateInquiryTimeout, whichever comes first.
func queryParentKeyStateDetailed(ctx context.Context, hdb *HsyncDB, imr *Imr, keyName string, keyid uint16) (uint8, string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, parentKeyStateInquiryTimeout)
	defer cancel()
	ks, authenticated, err := tdns.QueryParentKeyState(ctx, hdb.KeyDB, imr.Imr, keyName, keyid)
	if err != nil {
		return 0, "", false, err
	}
	return ks.KeyState, ks.ExtraText, authenticated, nil
}

// parentKeyStateLine is what "parentsync inquire" prints for the parent's
// answer: the state, and whether the answer was authenticated. An answer that
// was not is one the agent accepted only because of its configuration, and
// the line names the setting, so that "Trusted" from a parent nobody verified
// does not read as the same thing as "Trusted" from one that was.
func parentKeyStateLine(state uint8, authenticated bool) string {
	line := "Parent says: " + edns0.KeyStateToString(state)
	if authenticated {
		return line + " (answer authenticated)"
	}
	return line + " (answer NOT authenticated; shown because parentsync.update.allow-insecure is set)"
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
