package tdnsmp

import (
	"testing"

	"github.com/johanix/tdns-transport/v2/transport"
)

// rearmFailedDiscovery: a peer whose discovery failed (top-level ERROR, no
// address, no mechanism past NEEDED) goes back to NEEDED so the transport's
// DiscoverPeer resolves it again; anything else is left alone.
func TestRearmFailedDiscovery(t *testing.T) {
	reg := transport.NewPeerRegistry()

	failed := reg.GetOrCreate("failed.example.")
	failed.SetState(transport.PeerStateError, "discovery failed")
	rearmFailedDiscovery(reg, "failed.example.")
	if got := failed.GetState(); got != transport.PeerStateNeeded {
		t.Errorf("failed peer: state %v, want NEEDED", got)
	}

	// ERROR at the top level but a mechanism already discovered: established
	// on that path, not re-armed.
	known := reg.GetOrCreate("known.example.")
	known.SetMechanismState("DNS", transport.PeerStateKnown, "discovered")
	known.SetState(transport.PeerStateError, "stale failure")
	rearmFailedDiscovery(reg, "known.example.")
	if got := known.GetState(); got != transport.PeerStateError {
		t.Errorf("known peer: state %v, want ERROR untouched", got)
	}

	// Not in ERROR: untouched.
	needed := reg.GetOrCreate("needed.example.")
	rearmFailedDiscovery(reg, "needed.example.")
	if got := needed.GetState(); got != transport.PeerStateNeeded {
		t.Errorf("needed peer: state %v, want NEEDED", got)
	}

	// Unknown identity and a nil registry: no-ops.
	rearmFailedDiscovery(reg, "absent.example.")
	rearmFailedDiscovery(nil, "failed.example.")
}
