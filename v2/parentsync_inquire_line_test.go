package tdnsmp

import (
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/edns0"
)

// The line "parentsync inquire" prints says whether the parent's answer was
// authenticated. An answer the agent accepted only because of its
// configuration names the setting, so the same state from a verified and
// from an unverified parent do not read alike.
func TestTheInquiryLineSaysWhetherTheAnswerWasAuthenticated(t *testing.T) {
	state := edns0.KeyStateToString(edns0.KeyStateUnknown)

	verified := parentKeyStateLine(edns0.KeyStateUnknown, true)
	if !strings.HasPrefix(verified, "Parent says: "+state) {
		t.Errorf("the line %q does not start with the state the parent reported", verified)
	}
	if strings.Contains(verified, "NOT") || !strings.Contains(verified, "authenticated") {
		t.Errorf("the line for an authenticated answer is %q", verified)
	}

	unverified := parentKeyStateLine(edns0.KeyStateUnknown, false)
	if !strings.HasPrefix(unverified, "Parent says: "+state) {
		t.Errorf("the line %q does not start with the state the parent reported", unverified)
	}
	if !strings.Contains(unverified, "NOT authenticated") || !strings.Contains(unverified, "parentsync.update.allow-insecure") {
		t.Errorf("the line for an answer that was not authenticated is %q, want it marked and the setting named", unverified)
	}
	if verified == unverified {
		t.Error("an authenticated and an unauthenticated answer print the same line")
	}
}
