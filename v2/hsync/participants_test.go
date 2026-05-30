/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

import (
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func TestParticipantsFromHSYNC3_offExcluded(t *testing.T) {
	on := mustHSYNC3RR(t, "fox", "fox.example.")
	off := mustHSYNC3RR(t, "hare", "hare.example.")
	off.Data.(*core.HSYNC3).State = 0

	got := ParticipantsFromHSYNC3([]dns.RR{on, off}, nil)
	if len(got) != 1 || got[0] != PeerID("fox.example.") {
		t.Fatalf("got %v, want [fox.example.]", got)
	}
}

func TestParticipantsFromHSYNC3_hsyncparamRoles(t *testing.T) {
	fox := mustHSYNC3RR(t, "fox", "fox.example.")
	hare := mustHSYNC3RR(t, "hare", "hare.example.")
	param := &core.HSYNCPARAM{
		Value: []core.HSYNCPARAMKeyValue{
			&core.HSYNCPARAMServers{Servers: []string{"fox"}},
		},
	}

	got := ParticipantsFromHSYNC3([]dns.RR{fox, hare}, param)
	if len(got) != 1 || got[0] != PeerID("fox.example.") {
		t.Fatalf("got %v, want [fox.example.]", got)
	}
}
