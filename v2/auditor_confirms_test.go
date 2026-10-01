package tdnsmp

import (
	"testing"

	"github.com/johanix/tdns-mp/v2/hsync"
	"github.com/johanix/tdns/v2/core"
)

// #101: the auditor answers a distribution with a final confirmation. The
// transport says PENDING on receipt; the auditor, its event logged, says
// SUCCESS, its task done, so the sender's trackers have their answer. The
// path is the one mpauditor runs: the engine's inbound handler and its
// record of the message. An RFI, or a message with no distribution ID,
// gets no confirmation.
func TestTheAuditorConfirmsADistributionAsSuccess(t *testing.T) {
	var got []*RemoteConfirmationDetail
	msgQs := &MsgQs{OnRemoteConfirmationReady: func(d *RemoteConfirmationDetail) { got = append(got, d) }}
	e := &AuditorEngine{msgQs: msgQs}

	key := testDnskey(t, "cell.example.", 257)
	msg := &AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{
		MessageType: core.AgentMsgNotify, OriginatorID: "agent.p1.example.", DeliveredBy: "agent.p1.example.",
		Zone: "cell.example.", DistributionID: "d1",
		Operations: []core.RROperation{{Operation: "replace", RRtype: "DNSKEY", Records: []string{key.String()}}},
	}}
	e.onInboundMsg(&hsync.InboundMsg{MessageType: hsync.AgentMsg(msg.MessageType), Originator: hsync.PeerID(msg.OriginatorID), Zone: hsync.ZoneName(msg.Zone), Payload: msg})

	if len(got) != 1 {
		t.Fatalf("%d confirmations, want 1", len(got))
	}
	d := got[0]
	if d.Status != "SUCCESS" || d.OriginatingDistID != "d1" || d.OriginatingSender != "agent.p1.example." || d.Zone != "cell.example." {
		t.Errorf("confirmation %+v, want SUCCESS for d1 to agent.p1.example. for cell.example.", d)
	}
	if len(d.AppliedRecords) != 1 || len(d.IgnoredRecords) != 0 || len(d.RejectedItems) != 0 {
		t.Errorf("records: applied %v ignored %v rejected %v, want the record done and nothing else", d.AppliedRecords, d.IgnoredRecords, d.RejectedItems)
	}

	// an RFI, and a message with no distribution ID: nothing to confirm
	e.recordSyncMsg(&AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{MessageType: core.AgentMsgRfi, RfiType: "CONFIG", OriginatorID: "agent.p1.example.", Zone: "cell.example.", DistributionID: "d2"}})
	e.recordSyncMsg(&AgentMsgPostPlus{AgentMsgPost: AgentMsgPost{MessageType: core.AgentMsgNotify, OriginatorID: "agent.p1.example.", Zone: "cell.example.",
		Records: map[string][]string{"cell.example.": {"cell.example. 300 IN A 192.0.2.1"}}}})
	if len(got) != 1 {
		t.Fatalf("a confirmation for an RFI or a distribution without ID: %+v", got[len(got)-1])
	}

	// an engine that was never started has no queues, and confirms nothing
	(&AuditorEngine{}).recordSyncMsg(msg)
	if len(got) != 1 {
		t.Fatal("an engine without queues sent a confirmation")
	}
}
