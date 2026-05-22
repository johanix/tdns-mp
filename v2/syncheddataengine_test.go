package tdnsmp

import (
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// TestSDE_AnswersDumpCommand is a regression guard for the silent-SDE
// footgun (2026-05-22): an agent's SynchedDataEngine must answer a
// SynchedDataCmd instead of leaving the API caller to time out.
//
// "dump-zonedatarepo" is the command behind `tdns-mpcli agent zone
// edits list`. The bug was that when the engine took its (now removed)
// inactive branch it only serviced SynchedDataUpdate and never read
// SynchedDataCmd, so the command sat unread in a buffered channel and
// the handler returned "No response from SynchedDataCmd after 2 seconds"
// with zero logs. This test would have caught that: it fails if the
// engine does not put a response on sdcmd.Response.
func TestSDE_AnswersDumpCommand(t *testing.T) {
	ctx := t.Context() // cancelled at test cleanup; stops the engine goroutine

	// Minimal config: no MPTransport, so the engine skips startup
	// hydration (RFI EDITS/KEYSTATE) and goes straight to its loop. No
	// MP zones, so the repo is empty — the dump still must answer.
	conf := &Config{Config: &tdns.Config{}}
	msgQs := &MsgQs{
		SynchedDataUpdate: make(chan *SynchedDataUpdate, 4),
		SynchedDataCmd:    make(chan *SynchedDataCmd, 4),
	}

	go conf.SynchedDataEngine(ctx, msgQs)

	resp := make(chan *SynchedDataCmdResponse, 1)
	msgQs.SynchedDataCmd <- &SynchedDataCmd{
		Cmd:      "dump-zonedatarepo",
		Response: resp,
	}

	select {
	case r := <-resp:
		if r == nil {
			t.Fatal("SynchedDataEngine returned a nil response")
		}
		if r.Error {
			t.Fatalf("dump-zonedatarepo returned an error: %s", r.ErrorMsg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SynchedDataEngine did not answer dump-zonedatarepo within 3s " +
			"(regression: engine not servicing SynchedDataCmd)")
	}
}
