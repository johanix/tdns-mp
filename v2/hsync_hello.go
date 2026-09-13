package tdnsmp

func (ar *AgentRegistry) HelloHandler(report *AgentMsgReport) {
	// log.Printf("HelloHandler: Received HELLO from %s", report.Identity)

	switch report.MessageType {
	case AgentMsgHello:
		lgAgent.Debug("received initial HELLO", "from", report.Identity)
		// Store in wannabe_agents until we verify it shares zones with us
		// wannabe_agents[report.Msg.Identity] = report.Agent

	default:
		lgAgent.Warn("unknown message type in HelloHandler", "type", AgentMsgToString[report.MessageType])
	}
}
