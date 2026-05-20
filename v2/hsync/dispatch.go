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

// InboundMsg is a generic application message for role-specific handlers.
type InboundMsg struct {
	MessageType AgentMsg
	Originator  PeerID
	Zone        ZoneName
	Payload     interface{}
}

// SyncHandler processes inbound zone-data sync messages (agent only).
type SyncHandler func(msg *InboundMsg)

// ElectionHandler processes inbound election messages.
type ElectionHandler func(msg *InboundMsg)

// KeyStateHandler processes inbound keystate messages.
type KeyStateHandler func(msg *InboundMsg)

func (e *Engine) dispatchMsg(msg *InboundMsg) {
	if msg == nil {
		return
	}
	switch msg.MessageType {
	default:
		if e.onSync != nil {
			e.onSync(msg)
		}
	}
}

func (e *Engine) dispatchByType(msg *InboundMsg) {
	if msg == nil {
		return
	}
	// Election and keystate subtypes are routed by embedding role at wire-in time.
	if e.onElection != nil && isElectionMsg(msg.MessageType) {
		e.onElection(msg)
		return
	}
	if e.onKeyState != nil && isKeyStateMsg(msg.MessageType) {
		e.onKeyState(msg)
		return
	}
	if e.onSync != nil {
		e.onSync(msg)
	}
}

func isElectionMsg(_ AgentMsg) bool {
	return false
}

func isKeyStateMsg(_ AgentMsg) bool {
	return false
}
