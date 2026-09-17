/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package main

import (
	"testing"

	"github.com/johanix/dnssec-algorithms/registry"
	algs "github.com/johanix/tdns/v2/algorithms"
)

// The registrations come from tdns-genalgs and the registry, so MLDSA44 is
// at the registry's codepoint, the one every tdns binary uses: a DNSKEY this
// signer emits means the same algorithm to the servers it signs for. The
// expected codepoint is read from the registry this module pins, not written
// here: it has moved before (199, then the IANA assignment), and generated
// files left over from an older registry checkout are exactly the drift this
// test is for.
//
// A default build has no algs.list (see algs.list.PQ-DNSSEC) and so no
// PQ-DNSSEC algorithm at all: nothing to compare, and the test is skipped.
func TestMLDSA44IsAtTheRegistryCodepoint(t *testing.T) {
	var want uint8
	inRegistry := false
	for _, a := range registry.Algorithms {
		if a.Name == "MLDSA44" {
			want, inRegistry = a.Codepoint, true
		}
	}
	if !inRegistry {
		t.Fatal("the registry this module pins has no MLDSA44")
	}
	n, ok := algs.AlgorithmNumber("MLDSA44")
	if !ok {
		t.Skip("built without the PQ-DNSSEC algorithms: no algs.list, nothing generated (see algs.list.PQ-DNSSEC)")
	}
	if n != want {
		t.Fatalf("MLDSA44 registered at %d, want the registry's %d: the generated files come from another registry than the one this module pins; run the generate step again", n, want)
	}
}
