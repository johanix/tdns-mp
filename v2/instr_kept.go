/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The lists a zone keeps, each in order, on disk (design 3.1, rules 3 and
 * 6, plans S6 and S8): the owed list, this provider's own changes made while
 * the zone is frozen, released when the transition is done; and the kept
 * list, other agents' distributions made under a serial this agent is not
 * active at, released at the activation. Both are kept apart from the
 * agent's data, which catch-up answers and syncs read: a kept change
 * reaches no peer and no parent before its release. Only the data engine
 * takes from them.
 */
package tdnsmp

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// listOwed is the owed list: this provider's own changes.
const listOwed = "owed"

// listKept is the kept list: other agents' distributions (plan S8).
const listKept = "kept"

// keptUpdate is an update as a list keeps it: what the data engine needs to
// handle it again, its records as text, each with its class. An entry of
// the kept list also keeps where the update came from: the agent it names,
// the one the transport established, the mechanism it came on, the
// sender's time, the stamp it was made under, and the request it answers.
type keptUpdate struct {
	Operations  []core.RROperation  `json:"operations,omitempty"`
	RRsets      map[string][]string `json:"rrsets,omitempty"` // by type
	RRs         []string            `json:"rrs,omitempty"`
	Force       bool                `json:"force,omitempty"`
	Sender      AgentId             `json:"sender,omitempty"`
	DeliveredBy AgentId             `json:"delivered_by,omitempty"`
	Mechanism   string              `json:"mechanism,omitempty"`
	Time        time.Time           `json:"time,omitzero"`
	Instr       *MsgStamp           `json:"instr,omitempty"`
	CatchUp     *CatchUp            `json:"catch_up,omitempty"`
}

// keptEntry is one entry of a list: its place, the sender's distribution
// (the kept list's; none on the owed list), the update and when it was
// kept.
type keptEntry struct {
	Seq          int64
	Distribution string
	Update       keptUpdate
	Since        time.Time
}

// keptLists are every zone's lists, in memory and in HsyncDB. Every change
// is written before it returns.
type keptLists struct {
	mu    sync.Mutex
	hdb   *HsyncDB                          // nil: in memory only
	lists map[string]map[string][]keptEntry // zone (folded) -> list -> entries, in order
	seq   int64
}

// loadKeptLists reads the lists kept on disk, at the agent's start.
func loadKeptLists(hdb *HsyncDB) (*keptLists, error) {
	k := &keptLists{hdb: hdb, lists: map[string]map[string][]keptEntry{}}
	if hdb == nil {
		return k, nil
	}
	hdb.Lock()
	defer hdb.Unlock()
	rows, err := hdb.DB.Query(`SELECT zonename, list, seq, distribution, update_json, since FROM MPKept ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("reading the kept lists: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var zone, list, upd, since string
		var e keptEntry
		if err := rows.Scan(&zone, &list, &e.Seq, &e.Distribution, &upd, &since); err != nil {
			return nil, fmt.Errorf("reading the kept lists: %w", err)
		}
		if err := json.Unmarshal([]byte(upd), &e.Update); err != nil {
			return nil, fmt.Errorf("the %s list of %s, entry %d: %w", list, zone, e.Seq, err)
		}
		e.Since, _ = time.Parse(time.RFC3339, since)
		k.put(zone, list, e)
		k.seq = max(k.seq, e.Seq)
	}
	return k, rows.Err()
}

// put appends e to the zone's list in memory. Called with mu held, or
// before k is shared.
func (k *keptLists) put(zone, list string, e keptEntry) {
	zone = canonicalName(zone)
	if k.lists[zone] == nil {
		k.lists[zone] = map[string][]keptEntry{}
	}
	k.lists[zone][list] = append(k.lists[zone][list], e)
}

// add puts u at the end of the zone's list, unless it repeats the entry at
// the end: a repeat is kept once. Reports whether it was added.
func (k *keptLists) add(zone, list, distribution string, u keptUpdate) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	entries := k.lists[canonicalName(zone)][list]
	if n := len(entries); n > 0 && entries[n-1].Distribution == distribution && reflect.DeepEqual(entries[n-1].Update, u) {
		return false, nil
	}
	e := keptEntry{Seq: k.seq + 1, Distribution: distribution, Update: u, Since: time.Now()}
	if k.hdb != nil {
		b, err := json.Marshal(u)
		if err != nil {
			return false, fmt.Errorf("keeping a change of %s: %w", zone, err)
		}
		k.hdb.Lock()
		_, err = k.hdb.DB.Exec(`INSERT INTO MPKept (zonename, list, seq, distribution, update_json, since) VALUES (?, ?, ?, ?, ?, ?)`,
			canonicalName(zone), list, e.Seq, distribution, string(b), e.Since.UTC().Format(time.RFC3339))
		k.hdb.Unlock()
		if err != nil {
			return false, fmt.Errorf("keeping a change of %s: %w", zone, err)
		}
	}
	k.seq = e.Seq
	k.put(zone, list, e)
	return true, nil
}

// keepOnce puts u, another agent's distribution, at the end of the zone's
// kept list, unless the list holds that sender's distribution already: a
// resend is kept once. Reports whether it was added.
func (k *keptLists) keepOnce(zone, distribution string, u keptUpdate) (bool, error) {
	if distribution != "" {
		k.mu.Lock()
		held := slices.ContainsFunc(k.lists[canonicalName(zone)][listKept], func(e keptEntry) bool {
			return e.Distribution == distribution && canonicalName(string(e.Update.Sender)) == canonicalName(string(u.Sender))
		})
		k.mu.Unlock()
		if held {
			return false, nil
		}
	}
	return k.add(zone, listKept, distribution, u)
}

// entries is the zone's list, in order; a copy.
func (k *keptLists) entries(zone, list string) []keptEntry {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.lists[canonicalName(zone)][list])
}

// remove takes the entry seq off the zone's list, on disk first.
func (k *keptLists) remove(zone, list string, seq int64) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.hdb != nil {
		k.hdb.Lock()
		_, err := k.hdb.DB.Exec(`DELETE FROM MPKept WHERE seq = ?`, seq)
		k.hdb.Unlock()
		if err != nil {
			return fmt.Errorf("releasing entry %d of the %s list of %s: %w", seq, list, zone, err)
		}
	}
	zone = canonicalName(zone)
	if k.lists[zone] == nil {
		return nil
	}
	k.lists[zone][list] = slices.DeleteFunc(k.lists[zone][list], func(e keptEntry) bool { return e.Seq == seq })
	if len(k.lists[zone][list]) == 0 {
		delete(k.lists[zone], list)
	}
	if len(k.lists[zone]) == 0 {
		delete(k.lists, zone)
	}
	return nil
}

// zones are the zones (folded) whose list is not empty, sorted.
func (k *keptLists) zones(list string) []string {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for zone, lists := range k.lists {
		if len(lists[list]) > 0 {
			out = append(out, zone)
		}
	}
	sort.Strings(out)
	return out
}

// keptUpdateOf is u as a list keeps it.
func keptUpdateOf(u *SynchedDataUpdate) keptUpdate {
	k := keptUpdate{Force: u.Force}
	if u.Update == nil {
		return k
	}
	k.Operations = slices.Clone(u.Update.Operations)
	for rrtype, rrset := range u.Update.RRsets {
		if len(rrset.RRs) == 0 {
			continue
		}
		if k.RRsets == nil {
			k.RRsets = map[string][]string{}
		}
		for _, rr := range rrset.RRs {
			k.RRsets[dns.TypeToString[rrtype]] = append(k.RRsets[dns.TypeToString[rrtype]], rr.String())
		}
	}
	for _, rr := range u.Update.RRs {
		k.RRs = append(k.RRs, rr.String())
	}
	return k
}

// keptRemoteOf is u, another agent's distribution, as the kept list keeps
// it.
func keptRemoteOf(u *SynchedDataUpdate) keptUpdate {
	k := keptUpdateOf(u)
	k.Sender, k.DeliveredBy, k.Mechanism, k.Time = u.AgentId, u.DeliveredBy, u.Mechanism, u.OriginatingTime
	k.Instr, k.CatchUp = u.OriginatingInstr, u.CatchUp
	return k
}

// remoteUpdate is the distribution the kept entry e keeps, for zone, as
// the data engine took it in.
func (e keptEntry) remoteUpdate(zone ZoneName) (*SynchedDataUpdate, error) {
	zu, err := e.Update.zoneUpdate(zone, e.Update.Sender)
	if err != nil {
		return nil, err
	}
	zu.CatchUp = e.Update.CatchUp
	return &SynchedDataUpdate{Zone: zone, AgentId: e.Update.Sender, UpdateType: "remote", Update: zu,
		OriginatingDistID: e.Distribution, OriginatingInstr: e.Update.Instr, Mechanism: e.Update.Mechanism,
		OriginatingTime: e.Update.Time, DeliveredBy: e.Update.DeliveredBy, CatchUp: e.Update.CatchUp, Force: e.Update.Force}, nil
}

// zoneUpdate is the update k keeps, for zone and agent, its records parsed
// again.
func (k keptUpdate) zoneUpdate(zone ZoneName, agent AgentId) (*ZoneUpdate, error) {
	zu := &ZoneUpdate{Zone: zone, AgentId: agent, RRsets: map[uint16]core.RRset{}, Operations: slices.Clone(k.Operations)}
	for typ, records := range k.RRsets {
		rrtype, ok := dns.StringToType[typ]
		if !ok {
			return nil, fmt.Errorf("a kept change of %s names the type %q", zone, typ)
		}
		rrset := core.RRset{RRtype: rrtype}
		for _, s := range records {
			rr, err := dns.NewRR(s)
			if err != nil {
				return nil, fmt.Errorf("a kept change of %s: %w", zone, err)
			}
			rrset.Name = rr.Header().Name
			rrset.RRs = append(rrset.RRs, rr)
		}
		zu.RRsets[rrtype] = rrset
	}
	for _, s := range k.RRs {
		rr, err := dns.NewRR(s)
		if err != nil {
			return nil, fmt.Errorf("a kept change of %s: %w", zone, err)
		}
		zu.RRs = append(zu.RRs, rr)
	}
	return zu, nil
}

// overOwed is base, this provider's own records of a zone by type, with the
// owed changes laid over it in order: what the operator's next edit and its
// view see (plan S6). A replace sets the type's records, an add or an RR of
// class IN adds one, and a delete or an RR of class NONE takes one away.
// (No owed change has class ANY: dns.NewRR, which reads the operator's
// records and the list's, refuses it.) base is not changed.
func overOwed(base map[uint16][]dns.RR, owed []keptEntry) map[uint16][]dns.RR {
	out := make(map[uint16][]dns.RR, len(base))
	for t, rrs := range base {
		out[t] = slices.Clone(rrs)
	}
	add := func(rr dns.RR) {
		t := rr.Header().Rrtype
		if !slices.ContainsFunc(out[t], func(o dns.RR) bool { return dns.IsDuplicate(o, rr) }) {
			out[t] = append(out[t], rr)
		}
	}
	del := func(rr dns.RR) {
		t := rr.Header().Rrtype
		out[t] = slices.DeleteFunc(out[t], func(o dns.RR) bool { return dns.IsDuplicate(o, rr) })
	}
	parse := func(s string, class uint16) dns.RR {
		rr, err := dns.NewRR(s)
		if err != nil || rr == nil {
			return nil
		}
		if class != 0 {
			rr.Header().Class = class
		}
		return rr
	}
	for _, e := range owed {
		if len(e.Update.Operations) > 0 {
			// the operations take precedence over the sets, as the engine
			// has it (ProcessUpdate)
			for _, op := range e.Update.Operations {
				rrtype, ok := dns.StringToType[op.RRtype]
				if !ok {
					continue
				}
				if op.Operation == "replace" {
					out[rrtype] = nil
				}
				for _, s := range op.Records {
					rr := parse(s, dns.ClassINET)
					if rr == nil {
						continue
					}
					if op.Operation == "delete" {
						del(rr)
					} else {
						add(rr)
					}
				}
			}
			continue
		}
		for _, records := range e.Update.RRsets {
			for _, s := range records {
				rr := parse(s, 0)
				if rr == nil {
					continue
				}
				none := rr.Header().Class == dns.ClassNONE
				rr.Header().Class = dns.ClassINET
				if none {
					del(rr)
				} else {
					add(rr)
				}
			}
		}
	}
	for t, rrs := range out {
		if len(rrs) == 0 {
			delete(out, t)
		}
	}
	return out
}
