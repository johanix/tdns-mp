/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"strings"
	"sync"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// keyStateHistory remembers, per zone and sender, the key states the
// sender's DNSKEY distributions gave, so that the event log can show what
// changed since the previous one: a provider resends its whole DNSKEY set,
// and the news is the one key whose state moved. It is the auditor's memory,
// not the message's, and starts empty with the process: the first
// distribution from each sender after a start shows no changes.
type keyStateHistory struct {
	mu   sync.Mutex
	last map[string]map[uint16]core.KeyState // zone and sender → key tag → state
}

// next returns what sender last said about its keys in zone, nil when that
// is not known, and records what ops say now. A DNSKEY replace sets the
// sender's whole set, an add sets the keys it names, and a delete removes
// the keys its records name. A key whose record comes without a state is
// remembered too, with what the sender said about it before or no state:
// the next message then knows the key is not new, and a replace that drops
// it lists it as no longer sent. A message without DNSKEY operations changes
// nothing. The maps handed out are never written again.
func (h *keyStateHistory) next(zone, sender string, ops []core.RROperation) map[uint16]core.KeyState {
	k := strings.ToLower(dns.Fqdn(zone)) + " " + strings.ToLower(dns.Fqdn(sender))
	h.mu.Lock()
	defer h.mu.Unlock()
	prev := h.last[k]
	cur := prev
	for _, op := range ops {
		if !strings.EqualFold(op.RRtype, "DNSKEY") {
			continue
		}
		var next map[uint16]core.KeyState
		switch op.Operation {
		case "replace":
			next = make(map[uint16]core.KeyState, len(op.KeyStates))
		case "add", "delete":
			next = make(map[uint16]core.KeyState, len(cur)+len(op.KeyStates))
			for tag, ks := range cur {
				next[tag] = ks
			}
		default:
			continue
		}
		for _, tag := range dnskeyTags(op.Records) {
			if op.Operation == "delete" {
				delete(next, tag)
				continue
			}
			if ks, ok := cur[tag]; ok {
				next[tag] = ks
			} else {
				next[tag] = core.KeyState{KeyTag: tag}
			}
		}
		if op.Operation != "delete" {
			for _, ks := range op.KeyStates {
				next[ks.KeyTag] = ks
			}
		}
		cur = next
	}
	if cur != nil {
		if h.last == nil {
			h.last = make(map[string]map[uint16]core.KeyState)
		}
		h.last[k] = cur
	}
	return prev
}

// dnskeyTags returns the key tags of the DNSKEY records among rrs.
func dnskeyTags(rrs []string) []uint16 {
	var tags []uint16
	for _, rrstr := range rrs {
		if rr, err := dns.NewRR(rrstr); err == nil {
			if key, ok := rr.(*dns.DNSKEY); ok {
				tags = append(tags, key.KeyTag())
			}
		}
	}
	return tags
}
