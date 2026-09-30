/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The auditor's final confirmation of a distribution (#101).
 */

package tdnsmp

// auditorConfirms sends the auditor's final confirmation of a distribution
// (#101). The transport answers PENDING on receipt, "forwarding to
// combiner"; an auditor has no combiner, so the second phase never came,
// and every sender waited for it: while an auditor was in the fleet no key
// distributed through the machine reached standby, and no withdrawn key
// left. The auditor is a participant like any other and its confirmation
// is part of the record, so it answers once its task is done. Its task is
// the event log, as an agent's is its combiner: the event logged, the
// distribution is done here, and that is SUCCESS, the records as done. It
// goes the way the agents' own final confirmations go, through
// OnRemoteConfirmationReady, to the originator. An auditor never delays or
// gates a change: it confirms every distribution it receives, at once.
// AuditorEngine.recordSyncMsg calls it after the event is logged; an RFI,
// or a message with no distribution ID, gets no confirmation.
func auditorConfirms(msgQs *MsgQs, msg *AgentMsgPostPlus, senderID, zone string) {
	if msgQs == nil || msgQs.OnRemoteConfirmationReady == nil || msg == nil || msg.DistributionID == "" {
		return
	}
	var recorded []string
	for _, rrs := range msg.Records {
		recorded = append(recorded, rrs...)
	}
	for _, op := range msg.Operations {
		recorded = append(recorded, op.Records...)
	}
	msgQs.OnRemoteConfirmationReady(&RemoteConfirmationDetail{
		OriginatingDistID: msg.DistributionID,
		OriginatingSender: senderID,
		Zone:              ZoneName(zone),
		Status:            "SUCCESS",
		Message:           "auditor: recorded",
		AppliedRecords:    recorded,
	})
	lgAuditor.Info("confirmed to the originator: recorded", "zone", zone, "originator", senderID, "distrib", msg.DistributionID, "records", len(recorded))
}
