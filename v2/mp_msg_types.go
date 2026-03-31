/*
 * Message queue types and message structs for multi-provider communication.
 * Copied from tdns/v2/config.go during agent extraction.
 */

package tdnsmp

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
}

type KeystateSignalMsg struct {
	SenderID string
	Zone     string
	KeyTag   uint16
	Signal   string
	Message  string
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
