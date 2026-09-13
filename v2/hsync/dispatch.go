/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package hsync

// MsgChannels are protocol queues fed by MPTransportBridge (D-1).
type MsgChannels struct {
	Hello <-chan *InboundReport
	Beat  <-chan *InboundReport
	Msg   <-chan *InboundMsg
}

// InboundMsg is a generic application message for the host's handler.
type InboundMsg struct {
	MessageType AgentMsg
	Originator  PeerID
	Zone        ZoneName
	Payload     interface{}
}

// InboundHandler receives every application message the engine is fed.
// The engine does not dispatch by message class (cleanup plan, step 6: the
// election and key-state slots it once had were never reached); the host
// looks at MessageType itself.
type InboundHandler func(msg *InboundMsg)
