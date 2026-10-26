/*
 * The message queues the engines and handlers exchange work through, and
 * the messages that ride on them.
 */

package tdnsmp

import (
	"time"

	core "github.com/johanix/tdns/v2/core"
)

// MsgQs aggregates channels for agent-to-agent communication.
// Each role (agent, combiner, signer) uses only the channels
// it needs; unused channels are nil.
type MsgQs struct {
	Hello             chan *AgentMsgReport
	Beat              chan *AgentMsgReport
	Ping              chan *AgentMsgReport
	Msg               chan *AgentMsgPostPlus
	Command           chan *AgentMgmtPostPlus
	DebugCommand      chan *AgentMgmtPostPlus
	SynchedDataUpdate chan *SynchedDataUpdate
	SynchedDataCmd    chan *SynchedDataCmd
	Confirmation      chan *ConfirmationDetail
	KeystateInventory chan *KeystateInventoryMsg
	KeystateSignal    chan *KeystateSignalMsg
	StatusUpdate      chan *StatusUpdateMsg

	// Answers to RFI EDITS, CONFIG and AUDIT, each handed to the request
	// that asked for it (see rfiWaiters).
	editsWaiters  rfiWaiters[*EditsResponseMsg]
	configWaiters rfiWaiters[*ConfigResponseMsg]
	auditWaiters  rfiWaiters[*AuditResponseMsg]

	// The KEYSTATE inventories that found KeystateInventory full, the
	// newest of each zone (#210).
	keystateOverflow inventoryOverflow

	OnRemoteConfirmationReady func(detail *RemoteConfirmationDetail)
}

type KeystateInventoryMsg struct {
	SenderID  string
	Zone      string
	Inventory []KeyInventoryItem
	Owned     bool     // the signer's own state machine runs the zone's keys (S3)
	Resend    []uint16 // keys the signer sends again: distributed even unchanged (#256)
	// seq: the order the agent's transport received it in; 0 for one that
	// was not counted. An inventory older than the zone's recorded one is
	// not recorded (noteKeyInventory): an RFI's answer can reach the engine
	// after a newer push that found the requester answered.
	seq uint64
}

type KeystateSignalMsg struct {
	SenderID string
	Zone     string
	KeyTag   uint16
	Signal   string
	Message  string
	At       time.Time // when the distribution the signal answers was sent; zero when the sender does not say
	// ForeignKeys: Signal "foreign", what the other providers said about
	// their keys in the zone (the complete latest set)
	ForeignKeys []core.ForeignKeyState
	// ForeignSpoken: Signal "foreign", the providers whose word the agent
	// holds, one that listed no keys included; nil from an older agent
	ForeignSpoken []string
}

type EditsResponseMsg struct {
	SenderID     string
	Zone         string
	AgentRecords map[string]map[string][]string
	// Message is the combiner's word on its answer: editsLoaded or
	// editsNotLoaded, or anything else from a combiner that has neither.
	Message string
}

// The combiner's word on its answer to RFI EDITS. An agent takes the answer
// as its own state only on editsLoaded. editsNotLoaded is applied to
// nothing. Any other word, from a combiner older than its agent, is applied
// as it always was, and does not count as the agent's own read: an agent
// whose combiner has failed to read its store would otherwise answer a
// request for the zone's state with empty sets, and remove its records at
// every peer.
const (
	editsLoaded    = "contributions-loaded"
	editsNotLoaded = "contributions-not-loaded"
)

type ConfigResponseMsg struct {
	SenderID   string
	Zone       string
	Subtype    string
	ConfigData map[string]string
}

// configRefusedKey is the ConfigData key of the answer to a CONFIG request
// the peer refused: its value is the peer's reason.
const configRefusedKey = "refused"

// Refused is the peer's reason for refusing the CONFIG request, or "" when
// it answered it.
func (m *ConfigResponseMsg) Refused() string {
	if m == nil {
		return ""
	}
	return m.ConfigData[configRefusedKey]
}

type AuditResponseMsg struct {
	SenderID  string
	Zone      string
	AuditData interface{}
}

type StatusUpdateMsg struct {
	SenderID  string
	Zone      string
	SubType   string
	NSRecords []string
	DSRecords []string
	Result    string
	Msg       string
}

type MessageRetentionConf struct {
	Beat     int `yaml:"beat" mapstructure:"beat"`
	Ping     int `yaml:"ping" mapstructure:"ping"`
	Hello    int `yaml:"hello" mapstructure:"hello"`
	Sync     int `yaml:"sync" mapstructure:"sync"`
	Relocate int `yaml:"relocate" mapstructure:"relocate"`
	Default  int `yaml:"default" mapstructure:"default"`
}

func (m *MessageRetentionConf) GetRetentionForMessageType(messageType string) int {
	const (
		defaultBeatPing = 30
		defaultOther    = 300
	)

	switch messageType {
	case "beat":
		if m.Beat > 0 {
			return m.Beat
		}
		return defaultBeatPing
	case "ping":
		if m.Ping > 0 {
			return m.Ping
		}
		return defaultBeatPing
	case "hello":
		if m.Hello > 0 {
			return m.Hello
		}
		return defaultOther
	case "sync":
		if m.Sync > 0 {
			return m.Sync
		}
		return defaultOther
	case "relocate":
		if m.Relocate > 0 {
			return m.Relocate
		}
		return defaultOther
	default:
		if m.Default > 0 {
			return m.Default
		}
		return defaultOther
	}
}
