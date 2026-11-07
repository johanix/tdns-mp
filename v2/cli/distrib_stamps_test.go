/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"bytes"
	"testing"
	"time"

	tdnsmp "github.com/johanix/tdns-mp/v2"
)

// `agent distrib stamps` prints each distribution's stamps per recipient
// (plan S5b): this agent's at its latest send, the recipient's at its
// latest confirmation, as active/newest, "-" for none.
func TestTheDistributionStampsArePrinted(t *testing.T) {
	at := time.Date(2026, 10, 28, 15, 4, 5, 0, time.UTC)
	sd := func(serial uint32) *tdnsmp.SerialDigest { return &tdnsmp.SerialDigest{Serial: serial, Digest: "d"} }
	var b bytes.Buffer
	printDistributionStamps(&b, []tdnsmp.DistributionStamps{
		{DistributionID: "2b8f0c1e", Recipient: "agent.bravo.example.", Sent: sd(6), SentNewest: sd(7), SentAt: at,
			Confirmed: sd(6), ConfirmedNew: sd(7), Status: "SUCCESS", ConfirmedAt: at.Add(time.Second)},
		{DistributionID: "2b8f0c1f", Recipient: "auditor.golf.example.", Sent: sd(7), SentNewest: sd(7), SentAt: at},
	})
	out := b.String()
	wantLines(t, "stamps", out,
		"Distribution  Receiver                      Sent       Sent at   Confirmed  Status    Confirmed at",
		"2b8f0c1e      agent.bravo.example.          6/7        15:04:05  6/7        SUCCESS   15:04:06",
		"2b8f0c1f      auditor.golf.example.         7/7        15:04:05  -          -         -")
	wantNoControls(t, "stamps", out)

	b.Reset()
	printDistributionStamps(&b, nil)
	wantLines(t, "no stamps", b.String(), "No distribution with stamps")
}
