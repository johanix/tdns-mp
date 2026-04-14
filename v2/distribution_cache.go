/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Distribution cache: in-memory tracking of chunk distributions.
 */
package tdnsmp

import (
	"context"
	"time"

	"github.com/johanix/tdns/v2/core"
)

// DistributionInfo holds information about a distribution
type DistributionInfo struct {
	DistributionID string
	SenderID       string
	ReceiverID     string
	Operation      string
	ContentType    string
	State          string
	PayloadSize    int // Size of the final payload in bytes (after encryption, before chunking)
	CreatedAt      time.Time
	CompletedAt    *time.Time
	ExpiresAt      *time.Time // When this distribution should be cleaned up (nil = no expiration)
	QNAME          string     // The DNS QNAME used to retrieve this distribution
}

// PeerInfo holds information about a peer agent with established keys
type PeerInfo struct {
	PeerID       string
	PeerType     string // "combiner" or "agent"
	Transport    string // "API" or "DNS"
	Address      string
	CryptoType   string    // "JOSE" or "HPKE" (for DNS), "TLS" (for API), or "-"
	DistribSent  int       // Number of distributions sent to this peer (deprecated - use TotalReceived)
	LastUsed     time.Time // Last time this peer was used
	Addresses    []string  // IP addresses from discovery
	Port         uint16    // Port number
	JWKData      string    // JWK data if available
	KeyAlgorithm string    // Key algorithm (e.g., "ES256")
	HasJWK       bool      // Whether JWK is available
	HasKEY       bool      // Whether KEY record is available
	HasTLSA      bool      // Whether TLSA record is available
	APIUri       string    // Full API URI
	DNSUri       string    // Full DNS URI
	Partial      bool      // Whether discovery was partial
	State        string    // Agent state
	ContactInfo  string    // Contact info status

	// Per-message-type statistics
	HelloSent     uint64
	HelloReceived uint64
	BeatSent      uint64
	BeatReceived  uint64
	SyncSent      uint64
	SyncReceived  uint64
	PingSent      uint64
	PingReceived  uint64
	TotalSent     uint64
	TotalReceived uint64
}

// DistributionCache is an in-memory cache of distributions keyed by QNAME
type DistributionCache struct {
	dists core.ConcurrentMap[string, *DistributionInfo] // keyed by QNAME
}

// NewDistributionCache creates a new distribution cache
func NewDistributionCache() *DistributionCache {
	return &DistributionCache{
		dists: *core.NewCmap[*DistributionInfo](),
	}
}

// Add adds a distribution to the cache
func (dc *DistributionCache) Add(qname string, info *DistributionInfo) {
	dc.dists.Set(qname, info)
}

// Get retrieves a distribution by QNAME
func (dc *DistributionCache) Get(qname string) (*DistributionInfo, bool) {
	return dc.dists.Get(qname)
}

// MarkCompleted marks a distribution as completed
func (dc *DistributionCache) MarkCompleted(qname string) {
	if info, exists := dc.dists.Get(qname); exists {
		now := time.Now()
		info.CompletedAt = &now
		info.State = "confirmed"
		dc.dists.Set(qname, info) // Update in map
	}
}

// List returns all distributions for a given sender
func (dc *DistributionCache) List(senderID string) []*DistributionInfo {
	var results []*DistributionInfo

	for tuple := range dc.dists.IterBuffered() {
		info := tuple.Val
		if senderID == "" || info.SenderID == senderID {
			results = append(results, info)
		}
	}
	return results
}

// PurgeCompleted removes completed distributions older than the given duration.
// Incomplete distributions (CompletedAt == nil) are never purged; only explicit "purge --force" removes them.
func (dc *DistributionCache) PurgeCompleted(olderThan time.Duration) int {
	count := 0
	cutoff := time.Now().Add(-olderThan)

	for tuple := range dc.dists.IterBuffered() {
		qname := tuple.Key
		info := tuple.Val
		if info.CompletedAt != nil && info.CompletedAt.Before(cutoff) {
			dc.dists.Remove(qname)
			count++
		}
	}
	return count
}

// PurgeAll removes all distributions
func (dc *DistributionCache) PurgeAll() int {
	count := dc.dists.Count()
	dc.dists.Clear()
	return count
}

// PurgeExpired removes distributions that have passed their ExpiresAt time.
// This implements fast expiration for beat/ping messages to reduce clutter.
// Returns the number of distributions removed.
func (dc *DistributionCache) PurgeExpired() int {
	count := 0
	now := time.Now()

	for tuple := range dc.dists.IterBuffered() {
		qname := tuple.Key
		info := tuple.Val
		if info.ExpiresAt != nil && info.ExpiresAt.Before(now) {
			dc.dists.Remove(qname)
			count++
		}
	}
	return count
}

// StartCleanupGoroutine starts a background goroutine that periodically
// removes expired distributions.
func (dc *DistributionCache) StartCleanupGoroutine(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				lgApi.Info("cleanup goroutine stopping")
				return
			case <-ticker.C:
				removed := dc.PurgeExpired()
				if removed > 0 {
					lgApi.Info("purged expired distributions", "count", removed)
				}
			}
		}
	}()
	lgApi.Info("cleanup goroutine started", "interval", "1m")
}

// StartDistributionGC starts garbage collection for completed and expired
// distributions.
func StartDistributionGC(cache *DistributionCache, interval time.Duration, stopCh chan struct{}) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				completedCount := cache.PurgeCompleted(5 * time.Minute)
				if completedCount > 0 {
					lgApi.Info("GC purged completed distributions", "count", completedCount)
				}

				expiredCount := cache.PurgeExpired()
				if expiredCount > 0 {
					lgApi.Info("GC purged expired distributions", "count", expiredCount)
				}
			case <-stopCh:
				return
			}
		}
	}()
}

// DistributionSummary contains summary information about a distribution
type DistributionSummary struct {
	DistributionID string `json:"distribution_id"`
	SenderID       string `json:"sender_id"`
	ReceiverID     string `json:"receiver_id"`
	Operation      string `json:"operation"`
	ContentType    string `json:"content_type"`
	State          string `json:"state"`
	PayloadSize    int    `json:"payload_size"`
	CreatedAt      string `json:"created_at"`
	CompletedAt    string `json:"completed_at,omitempty"`
}

// AgentDistribPost represents a request to the agent distrib API
type AgentDistribPost struct {
	Command       string `json:"command"`                  // "list", "purge", "peer-list", "peer-zones", "zone-agents", "op", "discover"
	Force         bool   `json:"force,omitempty"`          // for purge
	Op            string `json:"op,omitempty"`             // for op: operation name (e.g. "ping")
	To            string `json:"to,omitempty"`             // for op: recipient identity (e.g. "combiner", "agent.delta.dnslab.")
	PingTransport string `json:"ping_transport,omitempty"` // for op ping: "dns" (default) or "api"
	AgentId       string `json:"agent_id,omitempty"`       // for discover: agent identity to discover
	Zone          string `json:"zone,omitempty"`           // for zone-agents: zone name to list agents for
}

// AgentDistribResponse represents a response from the agent distrib API
type AgentDistribResponse struct {
	Time          time.Time              `json:"time"`
	Error         bool                   `json:"error,omitempty"`
	ErrorMsg      string                 `json:"error_msg,omitempty"`
	Msg           string                 `json:"msg,omitempty"`
	Summaries     []*DistributionSummary `json:"summaries,omitempty"`
	Distributions []string               `json:"distributions,omitempty"` // For backward compatibility
	Data          []interface{}          `json:"data,omitempty"`          // For peer-zones command
	Agents        []string               `json:"agents,omitempty"`        // For zone-agents command
}
