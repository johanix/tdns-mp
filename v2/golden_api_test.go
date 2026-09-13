/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The HTTPS bodies, byte-locked (cleanup plan step 5, first commit).
 *
 * The goldens in testdata/golden-api are what the HTTPS endpoints decoded
 * and the senders produced before the mechanism was rerouted through the
 * receive pipeline, with fixed inputs. A request body is what a peer posts
 * to /hello, /beat, /sync/ping and /msg; a response body is what it reads
 * back. Any key, order or omission rule that changes fails here.
 */

package tdnsmp

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func apiGoldenFixtures() map[string]interface{} {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return map[string]interface{}{
		"hello-request": &AgentHelloPost{MessageType: AgentMsgHello, MyIdentity: "a.example.", YourIdentity: "b.example.", Zone: "z.example.", Time: at},
		"beat-request":  &AgentBeatPost{MessageType: AgentMsgBeat, MyIdentity: "a.example.", YourIdentity: "b.example.", MyBeatInterval: 30, Zones: []string{"z1.example.", "z2.example."}, Time: at},
		"ping-request":  &AgentPingPost{MessageType: AgentMsgPing, MyIdentity: "a.example.", YourIdentity: "b.example.", Nonce: "n-1", Time: at},
		"msg-sync-request": &AgentMsgPost{MessageType: AgentMsgNotify, OriginatorID: "a.example.", YourIdentity: "b.example.", Zone: "z.example.",
			Records: map[string][]string{"z.example.": {"z.example. 3600 IN NS ns1.a.example."}}, Time: at},
		"msg-rfi-request": &AgentMsgPost{MessageType: AgentMsgRfi, OriginatorID: "a.example.", YourIdentity: "b.example.", Zone: "z.example.", RfiType: "CONFIG", RfiSubtype: "upstream", Time: at},
		"hello-response":  &AgentHelloResponse{Status: "ok", MyIdentity: "b.example.", YourIdentity: "a.example.", Time: at, Msg: "Hello there, a.example.!"},
		"hello-rejected":  &AgentHelloResponse{MyIdentity: "b.example.", YourIdentity: "a.example.", Time: at, Error: true, ErrorMsg: "Error: Zone \"z.example.\" participants do not include both our identities"},
		"beat-response":   &AgentBeatResponse{Status: "ok", MyIdentity: "b.example.", YourIdentity: "a.example.", Time: at, Msg: "Hi there!"},
		"ping-response":   &AgentPingResponse{Status: "ok", MyIdentity: "b.example.", YourIdentity: "a.example.", Nonce: "n-1", Time: at},
		"msg-response":    &AgentMsgResponse{Status: "ok", Time: at, Msg: "Hi there!"},
	}
}

func TestGoldenAPIBodies(t *testing.T) {
	for name, v := range apiGoldenFixtures() {
		got, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, err := os.ReadFile("testdata/golden-api/" + name + ".json")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s changed:\n got  %s\n want %s", name, got, want)
		}
	}
}
