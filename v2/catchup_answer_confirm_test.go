/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"log/slog"
	"strings"
	"testing"
)

// The asker confirms an answer to its request for the zone's state as it
// confirms any update. The answer is not tracked, so in a zone where the
// answering agent tracks nothing the confirmation is no loss of tracking and
// gives no warning. A confirmation that is no such answer still does.
func TestAConfirmationOfACatchUpAnswerIsNotALossOfTracking(t *testing.T) {
	const zone, asker = "answered.confirm.example.", "agent.asker.example."
	var buf lockedBuffer
	saved := lgEngine
	lgEngine = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { lgEngine = saved })

	zdr, err := NewZoneDataRepo()
	if err != nil {
		t.Fatal(err)
	}
	zdr.catchUpAnswers = map[ZoneName]map[AgentId]string{zone: {asker: "answer-dist"}}
	confirm := func(distID string) {
		zdr.ProcessConfirmation(&ConfirmationDetail{Source: asker, Zone: zone, DistributionID: distID, Status: "SUCCESS"}, nil)
	}

	confirm("answer-dist")
	if strings.Contains(buf.String(), "no tracking data for zone") {
		t.Errorf("the confirmation of a catch-up answer warned:\n%s", buf.String())
	}
	confirm("some-other-dist")
	if !strings.Contains(buf.String(), "no tracking data for zone") {
		t.Errorf("a confirmation for a zone with no tracking that is no catch-up answer did not warn:\n%s", buf.String())
	}
}
