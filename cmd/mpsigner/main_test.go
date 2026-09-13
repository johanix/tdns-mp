/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package main

import (
	"testing"

	algs "github.com/johanix/tdns/v2/algorithms"
)

// The registrations come from tdns-genalgs and the registry, so MLDSA44 is
// at the registry's codepoint, the one every tdns binary uses: a DNSKEY this
// signer emits means the same algorithm to the servers it signs for. Needs
// the generated files (make generate).
func TestMLDSA44IsAtTheRegistryCodepoint(t *testing.T) {
	if n, ok := algs.AlgorithmNumber("MLDSA44"); !ok || n != 199 {
		t.Fatalf("MLDSA44 registered at %d (known=%v), want the registry's 199", n, ok)
	}
}
