package tdnsmp

// setForTest makes names the multi-provider zones, as a parse that found
// them leaves the set.
func (s *mpZoneNameSet) setForTest(names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collected = nil
	cp := append([]string(nil), names...)
	s.current.Store(&cp)
}

// includeForTest adds name to the multi-provider zones, as a parse that
// found it does, unless it is there already.
func (s *mpZoneNameSet) includeForTest(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.names()
	for _, n := range cur {
		if canonicalName(n) == canonicalName(name) {
			return
		}
	}
	next := append(append(make([]string, 0, len(cur)+1), cur...), name)
	s.current.Store(&next)
}
