package tdnsmp

import (
	"context"
	"testing"
	"time"

	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
)

// #101: the auditor answers a distribution with a final confirmation. The
// transport says PENDING on receipt; the auditor, which applies nothing,
// says IGNORED, the transport's word for persisted and not applied, so the
// sender's trackers have their answer. An RFI, or a message with no
// distribution ID, gets none.
func TestTheAuditorConfirmsADistributionAsIgnored(t *testing.T) {
	var got []*RemoteConfirmationDetail
	msgQs := &MsgQs{Msg: make(chan *AgentMsgPostPlus, 4), Hello: make(chan *AgentMsgReport), Beat: make(chan *AgentMsgReport), Ping: make(chan *AgentMsgReport),
		Confirmation: make(chan *ConfirmationDetail), StatusUpdate: make(chan *StatusUpdateMsg)}
	done := make(chan struct{}, 8)
	msgQs.OnRemoteConfirmationReady = func(d *RemoteConfirmationDetail) { got = append(got, d); done <- struct{}{} }
	conf := &Config{Config: &tdns.Config{}}
	conf.InternalMp.AgentRegistry = &AgentRegistry{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go AuditorMsgHandler(ctx, conf, msgQs, nil)

	key := testDnskey(t, "cell.example.", 257)
	msgQs.Msg <- &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{
		MessageType: core.AgentMsgNotify, OriginatorID: "agent.p1.example.", DeliveredBy: "agent.p1.example.",
		Zone: "cell.example.", DistributionID: "d1",
		Operations: []core.RROperation{{Operation: "replace", RRtype: "DNSKEY", Records: []string{key.String()}}},
	}}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the auditor sent no confirmation for the distribution")
	}
	if len(got) != 1 {
		t.Fatalf("%d confirmations, want 1", len(got))
	}
	d := got[0]
	if d.Status != "IGNORED" || d.OriginatingDistID != "d1" || d.OriginatingSender != "agent.p1.example." || d.Zone != "cell.example." {
		t.Errorf("confirmation %+v, want IGNORED for d1 to agent.p1.example. for cell.example.", d)
	}
	if len(d.IgnoredRecords) != 1 || len(d.AppliedRecords) != 0 {
		t.Errorf("records: ignored %v applied %v, want the record ignored and nothing applied", d.IgnoredRecords, d.AppliedRecords)
	}

	// an RFI, and a message with no distribution ID: nothing to confirm
	msgQs.Msg <- &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{MessageType: core.AgentMsgRfi, RfiType: "CONFIG", OriginatorID: "agent.p1.example.", Zone: "cell.example.", DistributionID: "d2"}}
	msgQs.Msg <- &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{MessageType: core.AgentMsgNotify, OriginatorID: "agent.p1.example.", Zone: "cell.example.",
		Records: map[string][]string{"cell.example.": {"cell.example. 300 IN A 192.0.2.1"}}}}
	select {
	case <-done:
		t.Fatalf("a confirmation for an RFI or a distribution without ID: %+v", got[len(got)-1])
	case <-time.After(300 * time.Millisecond):
	}
}
