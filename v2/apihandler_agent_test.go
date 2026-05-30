package tdnsmp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// TestAPIagentDebug_DumpZoneDataRepo is an end-to-end smoke test of the
// agent's debug request path: HTTP POST -> APIagentDebug handler ->
// MsgQs.SynchedDataCmd -> SynchedDataEngine -> response -> HTTP body.
//
// This is the path behind `tdns-mpcli agent zone edits list`. It is the
// layer that actually broke in the silent-SDE footgun (2026-05-22): the
// handler returned 200 with Error=true / "No response from
// SynchedDataCmd after 2 seconds" because nothing serviced the engine
// command channel. This test asserts a clean (Error=false) response, so
// it fails if any link in that chain stops carrying the request.
func TestAPIagentDebug_DumpZoneDataRepo(t *testing.T) {
	ctx := t.Context() // cancelled at cleanup; stops the engine goroutine

	msgQs := &MsgQs{
		SynchedDataUpdate: make(chan *SynchedDataUpdate, 4),
		SynchedDataCmd:    make(chan *SynchedDataCmd, 4),
		// APIagentDebug() os.Exit(1)s if DebugCommand is nil, so it must
		// be set even though dump-zonedatarepo doesn't use it.
		DebugCommand: make(chan *AgentMgmtPostPlus, 4),
	}
	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.MpConfig = &MultiProviderConf{Identity: "test-agent.example."}
	conf.InternalMp.MsgQs = msgQs

	go conf.SynchedDataEngine(ctx, msgQs)

	handler := conf.APIagentDebug()

	body, err := json.Marshal(AgentMgmtPost{Command: "dump-zonedatarepo"})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/agent/debug", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler(w, req)

	res := w.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", res.StatusCode)
	}

	var resp AgentMgmtResponse
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error {
		t.Fatalf("dump-zonedatarepo returned error: %s", resp.ErrorMsg)
	}
}
