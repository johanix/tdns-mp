package tdnsmp

// HeartbeatHandler consumes the beat reports the transport bridge routes
// to MsgQs.Beat. Since cleanup step 5 the same routeBeatMessage produces
// the report for a beat carried by either mechanism, and it merges the
// beat's gossip; nothing is left for the handler but the record.
func (ar *AgentRegistry) HeartbeatHandler(report *AgentMsgReport) {
	switch report.MessageType {
	case AgentMsgBeat:
		lgAgent.Debug("received BEAT", "from", report.Identity, "mechanism", report.Transport)
	default:
		lgAgent.Warn("unknown message type in HeartbeatHandler", "type", AgentMsgToString[report.MessageType])
	}
}
