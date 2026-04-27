/*
 * Type definitions migrated from tdns to tdns-mp (wire-compatible copies).
 */

package tdnsmp

import (
	"time"

	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	DnskeyStateMpdist   = "mpdist"
	DnskeyStateMpremove = "mpremove"
	DnskeyStateForeign  = "foreign"
)

// RRsetString is the string-based RRset shape used in combiner JSON responses.
type RRsetString struct {
	Name   string   `json:"name"`
	RRtype uint16   `json:"rrtype"`
	RRs    []string `json:"rrs"`
	RRSIGs []string `json:"rrsigs,omitempty"`
}

// Combiner API types
type CombinerPost struct {
	Command string              `json:"command"` // add, list, remove
	Zone    string              `json:"zone"`    // zone name
	Data    map[string][]string `json:"data"`    // The RRs as strings, indexed by owner name
}

type CombinerResponse struct {
	Time     time.Time                `json:"time"`
	Error    bool                     `json:"error"`
	ErrorMsg string                   `json:"error_msg,omitempty"`
	Msg      string                   `json:"msg,omitempty"`
	Data     map[string][]RRsetString `json:"data,omitempty"`
}

type CombinerEditPost struct {
	Command string   `json:"command"` // "list", "list-approved", "list-rejected", "approve", "reject", "clear", "purge"
	Zone    string   `json:"zone"`
	EditID  int      `json:"edit_id,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Tables  []string `json:"tables,omitempty"` // for "clear": which tables to clear; empty = all
	Origin  string   `json:"origin,omitempty"` // for "purge": sender ID whose contributions to remove
}

type CombinerEditResponse struct {
	Time     time.Time                      `json:"time"`
	Error    bool                           `json:"error"`
	ErrorMsg string                         `json:"error_msg,omitempty"`
	Msg      string                         `json:"msg,omitempty"`
	Pending  []*PendingEditRecord           `json:"pending,omitempty"`
	Approved []*ApprovedEditRecord          `json:"approved,omitempty"`
	Rejected []*RejectedEditRecord          `json:"rejected,omitempty"`
	Current  map[string]map[string][]string `json:"current,omitempty"` // agent → rrtype → []rr
}

type CombinerDebugPost struct {
	Command string                 `json:"command"`
	Zone    string                 `json:"zone,omitempty"`
	AgentID string                 `json:"agent_id,omitempty"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

type CombinerDebugResponse struct {
	Time               time.Time                                            `json:"time"`
	Error              bool                                                 `json:"error"`
	ErrorMsg           string                                               `json:"error_msg,omitempty"`
	Msg                string                                               `json:"msg,omitempty"`
	Data               interface{}                                          `json:"data,omitempty"`
	CombinerData       map[string]map[string]map[string][]string            `json:"combiner_data,omitempty"`       // zone → owner → rrtype → []rr
	AgentContributions map[string]map[string]map[string]map[string][]string `json:"agent_contributions,omitempty"` // zone → agent → owner → rrtype → []rr
}

type CombinerDistribPost struct {
	Command string `json:"command"` // "list", "purge"
	Force   bool   `json:"force,omitempty"`
}

// CombinerDistribResponse defined locally (uses local DistributionSummary)
type CombinerDistribResponse struct {
	Time          time.Time              `json:"time"`
	Error         bool                   `json:"error,omitempty"`
	ErrorMsg      string                 `json:"error_msg,omitempty"`
	Msg           string                 `json:"msg,omitempty"`
	Summaries     []*DistributionSummary `json:"summaries,omitempty"`
	Distributions []string               `json:"distributions,omitempty"`
}

// Combiner sync types (local definitions; wire format matches tdns types)
type CombinerSyncRequest struct {
	SenderID       string
	DeliveredBy    string
	Zone           string
	ZoneClass      string
	SyncType       string
	Records        map[string][]string
	Operations     []core.RROperation
	Publish        *core.PublishInstruction
	Serial         uint32
	DistributionID string
	Timestamp      time.Time
}

type CombinerSyncResponse struct {
	DistributionID string
	Zone           string
	Nonce          string
	Status         string
	Message        string
	AppliedRecords []string
	RemovedRecords []string
	RejectedItems  []RejectedItem
	IgnoredRecords []string
	Timestamp      time.Time
	DataChanged    bool
}

type RejectedItem struct {
	Record string
	Reason string
}

// Combiner edit record types (moved from db_combiner_edits.go)
type PendingEditRecord struct {
	EditID         int                 `json:"edit_id"`
	Zone           string              `json:"zone"`
	SenderID       string              `json:"sender_id"`
	DeliveredBy    string              `json:"delivered_by"`
	DistributionID string              `json:"distribution_id"`
	Records        map[string][]string `json:"records"`
	ReceivedAt     time.Time           `json:"received_at"`
}

type ApprovedEditRecord struct {
	EditID         int                 `json:"edit_id"`
	Zone           string              `json:"zone"`
	SenderID       string              `json:"sender_id"`
	DistributionID string              `json:"distribution_id"`
	Records        map[string][]string `json:"records"`
	ReceivedAt     time.Time           `json:"received_at"`
	ApprovedAt     time.Time           `json:"approved_at"`
}

type RejectedEditRecord struct {
	EditID         int                 `json:"edit_id"`
	Zone           string              `json:"zone"`
	SenderID       string              `json:"sender_id"`
	DistributionID string              `json:"distribution_id"`
	Records        map[string][]string `json:"records"`
	ReceivedAt     time.Time           `json:"received_at"`
	RejectedAt     time.Time           `json:"rejected_at"`
	Reason         string              `json:"reason"`
}

// Signer / keystore inventory types
type KeyInventoryItem struct {
	KeyTag    uint16
	Algorithm uint8
	Flags     uint16
	State     string // "created","mpdist","published","standby","active","retired","removed","foreign"
	KeyRR     string // Full DNSKEY RR string (public key data, no private key)
}

type DnssecKeyWithTimestamps struct {
	ZoneName    string
	KeyTag      uint16
	Algorithm   uint8
	Flags       uint16
	State       string
	KeyRR       string
	PublishedAt *time.Time
	RetiredAt   *time.Time
}

// KeyInventorySnapshot stores a complete key inventory received from the signer.
type KeyInventorySnapshot struct {
	SenderID  string
	Zone      string
	Inventory []KeyInventoryItem
	Received  time.Time
}

type AgentId string

func (id AgentId) String() string { return string(id) }

type ZoneName string

func (zn ZoneName) String() string { return string(zn) }

type ZoneUpdate struct {
	Zone       ZoneName
	AgentId    AgentId
	ZoneClass  string                   // "mp" (default) or "provider"
	RRsets     map[uint16]core.RRset    // remote updates are only per RRset (i.e. full replace)
	RRs        []dns.RR                 // local updates can be per RR
	Operations []core.RROperation       // explicit operations (takes precedence over RRsets/RRs)
	Publish    *core.PublishInstruction // KEY/CDS publication instruction for combiner
}

// OwnerData matches tdns.OwnerData; alias keeps *tdns.ZoneData.Data map types aligned.
type OwnerData = tdns.OwnerData

// ZoneRefreshAnalysis carries pre-refresh results for PostRefresh (mirrors tdns.ZoneRefreshAnalysis).
type ZoneRefreshAnalysis struct {
	DelegationChanged bool
	DelegationStatus  tdns.DelegationSyncStatus
	HsyncChanged      bool
	HsyncStatus       *HsyncStatus
	DnskeyChanged     bool
	DnskeyStatus      *DnskeyStatus
}

// Transaction API types
type TransactionPost struct {
	Command string `json:"command"`           // "open-outgoing", "open-incoming", "errors", "error-details"
	Last    string `json:"last,omitempty"`    // Duration filter for errors (e.g. "30m", "2h")
	DistID  string `json:"dist_id,omitempty"` // For error-details: specific distribution ID
}

type TransactionSummary struct {
	DistributionID string `json:"distribution_id"`
	Peer           string `json:"peer"` // Receiver (outgoing) or Sender (incoming)
	Operation      string `json:"operation"`
	Zone           string `json:"zone,omitempty"`
	Age            string `json:"age"`
	CreatedAt      string `json:"created_at"`
	State          string `json:"state,omitempty"`
}

type TransactionErrorSummary struct {
	DistributionID string `json:"distribution_id"`
	Age            string `json:"age"`
	Sender         string `json:"sender"`
	MessageType    string `json:"message_type"`
	ErrorMsg       string `json:"error_msg"`
	QNAME          string `json:"qname"`
	Timestamp      string `json:"timestamp"`
}

type TransactionResponse struct {
	Time         time.Time                  `json:"time"`
	Error        bool                       `json:"error,omitempty"`
	ErrorMsg     string                     `json:"error_msg,omitempty"`
	Msg          string                     `json:"msg,omitempty"`
	Transactions []*TransactionSummary      `json:"transactions,omitempty"`
	Errors       []*TransactionErrorSummary `json:"errors,omitempty"`
	ErrorDetail  *TransactionErrorSummary   `json:"error_detail,omitempty"`
}

// NewMsgQs creates and returns a *MsgQs with all channels initialized.
func NewMsgQs() *MsgQs {
	return &MsgQs{
		Hello:             make(chan *AgentMsgReport, 100),
		Beat:              make(chan *AgentMsgReport, 100),
		Ping:              make(chan *AgentMsgReport, 100),
		Msg:               make(chan *AgentMsgPostPlus, 100),
		Command:           make(chan *AgentMgmtPostPlus, 100),
		DebugCommand:      make(chan *AgentMgmtPostPlus, 100),
		SynchedDataUpdate: make(chan *SynchedDataUpdate, 100),
		SynchedDataCmd:    make(chan *SynchedDataCmd, 100),
		Confirmation:      make(chan *ConfirmationDetail, 100),
		KeystateInventory: make(chan *KeystateInventoryMsg, 10),
		KeystateSignal:    make(chan *KeystateSignalMsg, 10),
		EditsResponse:     make(chan *EditsResponseMsg, 10),
		ConfigResponse:    make(chan *ConfigResponseMsg, 10),
		AuditResponse:     make(chan *AuditResponseMsg, 10),
		StatusUpdate:      make(chan *StatusUpdateMsg, 10),
	}
}

// MPdata caches multi-provider membership and signing state for a zone.
// nil means the zone is not confirmed as a multi-provider zone (either OptMultiProvider
// is not set, or the zone owner hasn't declared it via HSYNC3+HSYNCPARAM, or we are
// not a listed provider). Populated during zone refresh by populateMPdata().
//
// NOTE: This is an MP type that lives in tdns (not tdns-mp) because it is
// a field of ZoneMPExtension, which is a field of ZoneData.
type MPdata struct {
	WeAreProvider bool                     // At least one of our agent identities matches an HSYNC3 Identity
	OurLabel      string                   // Our provider label from the matching HSYNC3 record
	WeAreSigner   bool                     // Our label appears in HSYNCPARAM signers (or zone is unsigned)
	OtherSigners  int                      // Count of other signers in HSYNCPARAM
	ZoneSigned    bool                     // HSYNCPARAM signers= is non-empty (zone uses multi-signer)
	Options       map[tdns.ZoneOption]bool // MP-specific options (future: migrate from zd.Options)
}
