/*
 * The message queues the engines and handlers exchange work through, and
 * the messages that ride on them.
 */

package tdnsmp

import "time"

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
	EditsResponse     chan *EditsResponseMsg
	ConfigResponse    chan *ConfigResponseMsg
	AuditResponse     chan *AuditResponseMsg
	StatusUpdate      chan *StatusUpdateMsg

	OnRemoteConfirmationReady func(detail *RemoteConfirmationDetail)
}

type KeystateInventoryMsg struct {
	SenderID  string
	Zone      string
	Inventory []KeyInventoryItem
	Owned     bool // the signer's own state machine runs the zone's keys (S3)
}

type KeystateSignalMsg struct {
	SenderID string
	Zone     string
	KeyTag   uint16
	Signal   string
	Message  string
	At       time.Time // when the distribution the signal answers was sent; zero when the sender does not say
}

type EditsResponseMsg struct {
	SenderID     string
	Zone         string
	AgentRecords map[string]map[string][]string
}

type ConfigResponseMsg struct {
	SenderID   string
	Zone       string
	Subtype    string
	ConfigData map[string]string
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
