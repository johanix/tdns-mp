/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The multi-provider zones, as the config parse finds them (tdns-mp #401).
 * tdns calls the multi-provider option handler for each zone on every
 * ParseZones, the reloads included, and readers range over the zones from
 * their own goroutines meanwhile. The handler collects the names; the set
 * readers see is an immutable snapshot, replaced whole.
 */
package tdnsmp

import (
	"sync"
	"sync/atomic"

	tdns "github.com/johanix/tdns/v2"
)

// mpZoneNameSet is the multi-provider zones: each once, by its name folded,
// spelled as its config spells it.
type mpZoneNameSet struct {
	mu        sync.Mutex
	collected []string // what the option handler found since the last refresh
	current   atomic.Pointer[[]string]
}

// add collects a zone the option handler found.
func (s *mpZoneNameSet) add(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collected = append(s.collected, name)
}

// refresh publishes the zones of the snapshot and those collected since,
// each once, that tdns holds with the multi-provider option now: a zone the
// config dropped, or that lost the option, leaves the set. That makes it
// right whenever it runs, also after a parse that failed half-way, so it
// runs wherever a reader needs the parse's result (MainInit, the reload
// hooks), with no need to know where a parse began.
func (s *mpZoneNameSet) refresh() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// a new slice: the snapshot's own is never written to
	cur := s.names()
	all := make([]string, 0, len(cur)+len(s.collected))
	all = append(append(all, cur...), s.collected...)
	var next []string
	seen := map[string]bool{}
	for _, name := range all {
		key := canonicalName(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		if zd, ok := tdns.Zones.Get(key); ok && zd.Options[tdns.OptMultiProvider] {
			next = append(next, name)
		}
	}
	s.collected = nil
	s.current.Store(&next)
}

// reset empties the set, before the first parse.
func (s *mpZoneNameSet) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collected = nil
	s.current.Store(nil)
}

// names is the snapshot: never changed after it is published, so a reader
// ranges over it with no lock.
func (s *mpZoneNameSet) names() []string {
	if p := s.current.Load(); p != nil {
		return *p
	}
	return nil
}

// mpZoneNames is the multi-provider zones of the last parse (mpZoneNameSet).
func (conf *Config) mpZoneNames() []string {
	return conf.InternalMp.mpZones.names()
}
