/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The signer's resolver: a signer that owns a zone starts one, because the
 * key machine asks it whether the parent still serves a retired KSK's DS;
 * and the machine's question is "unknown" until the resolver has published.
 */
package tdnsmp

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

func TestSignerStartsAResolverOnlyWhenItOwnsAZone(t *testing.T) {
	off, on := false, true
	for _, c := range []struct {
		name    string
		zones   []string
		active  *bool
		want    bool
		wantWhy bool
	}{
		{"owns nothing", nil, nil, false, false},
		{"owns nothing, resolver asked for", nil, &on, false, false},
		{"owns a zone", []string{"owned.example."}, nil, true, false},
		{"owns a zone, resolver on", []string{"owned.example."}, &on, true, false},
		{"owns a zone, resolver turned off", []string{"owned.example."}, &off, false, true},
	} {
		conf := &Config{Config: &tdns.Config{}}
		conf.SetMpConfig(&MultiProviderConf{Role: "signer", KeyLifecycleZones: c.zones})
		conf.Config.Imr.Active = c.active
		want, why := conf.signerResolverWanted()
		if want != c.want || (why != "") != c.wantWhy {
			t.Errorf("%s: wanted=%v why=%q, want wanted=%v why set=%v", c.name, want, why, c.want, c.wantWhy)
		}
	}
	// no multi-provider config at all
	if want, why := (&Config{Config: &tdns.Config{}}).signerResolverWanted(); want || why != "" {
		t.Errorf("no multi-provider config: wanted=%v why=%q", want, why)
	}
}

// Before the resolver has published, and in a signer without one, the
// machine's question about the parent's DS has no answer: the key waits.
func TestParentServesDSIsUnknownUntilTheResolverPublished(t *testing.T) {
	conf := &Config{Config: &tdns.Config{}}
	w := &signerWire{conf: conf}
	if present, known := w.ParentServesDS("owned.example.", 4711); present || known {
		t.Errorf("no readiness signal at all: present=%v known=%v, want unknown", present, known)
	}
	conf.Config.Internal.ImrReady = tdns.NewImrReadiness()
	if present, known := w.ParentServesDS("owned.example.", 4711); present || known {
		t.Errorf("resolver not published yet: present=%v known=%v, want unknown", present, known)
	}
	// published with no engine behind it (cannot happen in the daemon, which
	// stores the pointer first): still unknown, never a nil dereference
	conf.Config.Internal.ImrReady.Publish()
	if present, known := w.ParentServesDS("owned.example.", 4711); present || known {
		t.Errorf("published without an engine: present=%v known=%v, want unknown", present, known)
	}
}
