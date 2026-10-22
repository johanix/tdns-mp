/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The DNSSEC marks on peer states (#260). A peer whose discovery data is not
 * secure has a mark after its state: "(-)" for an insecure chain, "(!)" for
 * a bogus one. The state says what the reporter did with the data (NEEDED:
 * refused, as validation is required; OPERATIONAL: taken, as validation is
 * off), the mark says what the chain is. The daemon keeps the state plain
 * and sends the verdict beside it; the mark is added here, when printing.
 */
package cli

import (
	"fmt"
	"strings"
)

// chainMark is the mark for the DNSSEC verdict chain ("insecure", "bogus"),
// and "" for any other.
func chainMark(chain string) string {
	switch chain {
	case "insecure":
		return "(-)"
	case "bogus":
		return "(!)"
	}
	return ""
}

// chainLegend explains the marks.
var chainLegend = []string{
	"(-) = the peer's DNSSEC chain is insecure: its DNS data cannot be validated",
	"(!) = the peer's DNSSEC chain is bogus: its DNS data fails validation",
}

// printDnssecNotes prints what goes after a peer table or matrix when a
// state carries a mark or DNSSEC validation is not enforced somewhere (the nodes
// named in off): the warning that validation is not enforced, when it is, and the
// legend of the marks.
func printDnssecNotes(off []string, marked bool) {
	if len(off) == 0 && !marked {
		return
	}
	fmt.Println()
	if len(off) > 0 {
		fmt.Printf("WARNING: DNSSEC validation is not enforced on %s: a peer is used even when its DNS data does not validate\n",
			strings.Join(off, ", "))
	}
	for _, l := range chainLegend {
		fmt.Println(l)
	}
}
