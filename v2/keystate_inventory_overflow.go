package tdnsmp

import (
	"slices"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

// keystateInventorySeq counts the KEYSTATE inventories the agent's
// transport receives (KeystateInventoryMsg.seq).
var keystateInventorySeq atomic.Uint64

// inventoryLocks is a lock per zone (dns.CanonicalName), held while an
// inventory of the zone is recorded (noteKeyInventory). Taken by nothing
// else, and first: it cannot reverse the order of the locks taken under it.
var inventoryLocks sync.Map

func inventoryLock(zone string) *sync.Mutex {
	m, _ := inventoryLocks.LoadOrStore(dns.CanonicalName(zone), &sync.Mutex{})
	return m.(*sync.Mutex)
}

// inventoryRecordedHook, when set, runs in noteKeyInventory between the
// snapshot and the owner's copy (a seam for tests).
var inventoryRecordedHook func(msg *KeystateInventoryMsg)

// inventoryOverflow holds the KEYSTATE inventories that found the data
// engine's queue (MsgQs.KeystateInventory) full: one per zone, the newest, so
// that a burst (every zone's standby key in the same second) loses none
// (#210). An inventory that comes for a zone already waiting here replaces
// the one there and takes its keys sent again (Resend) along: the newer
// inventory says all the older one did about the keys, but a resend is the
// signer's word for its own push alone (#256).
//
// While anything waits here, every inventory waits here too, and the engine
// takes them only once it has read the queue empty (takeWaitingInventories).
// So the inventories of a zone are handled in the order they came, and what
// waits is taken after the last inventory that was queued before it.
type inventoryOverflow struct {
	mu      sync.Mutex
	waiting map[string]*KeystateInventoryMsg
	order   []string // the zones that wait, the first to come first
}

// offerKeystateInventory hands an inventory to the data engine without
// waiting for room: on the queue, unless the queue is full or something
// waits in the overflow, and then into the overflow. Reports whether it went
// into the overflow, and whether it replaced an older inventory of the zone
// there.
func (q *MsgQs) offerKeystateInventory(msg *KeystateInventoryMsg) (waits, replaced bool) {
	o := &q.keystateOverflow
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.order) == 0 {
		select {
		case q.KeystateInventory <- msg:
			return false, false
		default:
		}
	}
	zone := dns.CanonicalName(msg.Zone)
	if old := o.waiting[zone]; old != nil {
		newer := *msg
		newer.Resend = unionKeyTags(old.Resend, msg.Resend)
		o.waiting[zone] = &newer
		return true, true
	}
	if o.waiting == nil {
		o.waiting = map[string]*KeystateInventoryMsg{}
	}
	o.waiting[zone] = msg
	o.order = append(o.order, zone)
	return true, false
}

// takeWaitingInventories is the engine's, after each inventory it read from
// the queue: what waits in the overflow, the first zone to come first, once
// the queue is empty, and nothing while the queue still holds inventories
// that came before them.
func (q *MsgQs) takeWaitingInventories() []*KeystateInventoryMsg {
	o := &q.keystateOverflow
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.order) == 0 || len(q.KeystateInventory) > 0 {
		return nil
	}
	out := make([]*KeystateInventoryMsg, 0, len(o.order))
	for _, zone := range o.order {
		out = append(out, o.waiting[zone])
	}
	o.waiting, o.order = nil, nil
	return out
}

// unionKeyTags is a's tags, then those of b that a does not have.
func unionKeyTags(a, b []uint16) []uint16 {
	out := slices.Clone(a)
	for _, tag := range b {
		if !slices.Contains(out, tag) {
			out = append(out, tag)
		}
	}
	return out
}
