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
func queryParentKeyStateDetailed(hdb *HsyncDB, imr *Imr, keyName string, keyid uint16) (uint8, string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), parentKeyStateInquiryTimeout)
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
