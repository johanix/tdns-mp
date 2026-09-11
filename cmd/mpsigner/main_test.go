/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package main

import (
	"testing"

	algs "github.com/johanix/tdns/v2/algorithms"
)

// MLDSA44 is registered at 18, the DNSSEC algorithm number IANA assigned it.
func TestMLDSA44Codepoint(t *testing.T) {
	if n, ok := algs.AlgorithmNumber("MLDSA44"); !ok || n != 18 {
		t.Fatalf("MLDSA44 registered at %d (known=%v), want 18", n, ok)
	}
}
