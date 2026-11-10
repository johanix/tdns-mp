/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The per-zone hooks follow the zone's ZoneData, not its name (tdns-mp
 * #396). tdns builds a new ZoneData for a zone that a config reload removed
 * and a later one added back, and on its dynamic and catalog paths. What
 * tdns-mp registers on a zone at its start -- the refresh callbacks, the
 * first-load callbacks -- sits on the old one, so each is done again for
 * the new one, once, as a start does it.
 */
package tdnsmp

import (
	"sync"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// zoneOnce is what has been done once per ZoneData, filed by zone name: a
// zone whose ZoneData tdns replaces is not in it until it is done again for
// the new one. It holds one ZoneData per name, and prune lets go of those
// that tdns no longer holds.
type zoneOnce struct {
	mu   sync.Mutex
	done map[string]*tdns.ZoneData
}

// first marks zd and reports whether it was not marked before. A ZoneData
// that tdns no longer holds is refused: a lookup that built a wrapper and
// runs its hooks late, after a reload replaced the zone, must not take the
// mark from the live ZoneData, or the next reload registers the live one's
// hooks a second time.
func (o *zoneOnce) first(zd *tdns.ZoneData) bool {
	key := canonicalName(zd.ZoneName)
	o.mu.Lock()
	defer o.mu.Unlock()
	if live, ok := tdns.Zones.Get(key); !ok || live != zd {
		return false
	}
	if o.done[key] == zd {
		return false
	}
	if o.done == nil {
		o.done = map[string]*tdns.ZoneData{}
	}
	o.done[key] = zd
	return true
}

// prune forgets the zones that tdns no longer holds under the ZoneData
// marked, so that nothing here keeps a removed zone alive.
func (o *zoneOnce) prune() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for key, zd := range o.done {
		if live, ok := tdns.Zones.Get(key); !ok || live != zd {
			delete(o.done, key)
		}
	}
}

// installZoneHooks makes hooks the role's per-zone hooks from now on: they
// run for every wrapper MPZones builds, which is how a zone whose ZoneData
// tdns replaced gets them, whoever looks it up first. The role's start runs
// them itself for the zones it starts with, and calls this after. Each hook
// does its work once per ZoneData (zoneOnce).
func (conf *Config) installZoneHooks(hooks ...func(*MPZoneData)) {
	Zones.SetOnNew(func(mpzd *MPZoneData) {
		for _, h := range hooks {
			h(mpzd)
		}
	})
}

// firstLoadSetup is the MP zone's set-up before its first load, on every
// role: its MPdata, and on the signer the resigner's watchlist. tdns
// registers only zones whose config carries a signing option for periodic
// re-signing, and MP switches inline-signing on dynamically (MPPreRefresh),
// so a zone it switched on is put on the watchlist at its first load here.
// The signer's zones sign through tdns: the policy binds through the zone's
// dnssecpolicy, signOnceAfterPolicyBind signs and flips Ready, every
// refresh signs its staged scope, and the ResignerEngine renews.
func (conf *Config) firstLoadSetup(zd *MPZoneData) {
	if !zd.Options[tdns.OptMultiProvider] || !conf.InternalMp.firstLoadSetUp.first(zd.ZoneData) {
		return
	}
	zd.Lock()
	defer zd.Unlock()
	zd.EnsureMP()
	if zd.MP.MPdata != nil {
		cp := *zd.MP.MPdata
		zd.MP.MPdata = &cp
		zd.MP.MPdata.Options = map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true}
	} else {
		zd.MP.MPdata = &MPdata{
			Options: map[tdns.ZoneOption]bool{tdns.OptMultiProvider: true},
		}
	}
	// under the zone's lock, as tdns drains OnFirstLoad
	if tdns.Globals.App.Type == AppTypeMPSigner && zd.FirstZoneLoad {
		zd.OnFirstLoad = append(zd.OnFirstLoad, func(zd *tdns.ZoneData) {
			if !zd.Options[tdns.OptInlineSigning] {
				return
			}
			q := conf.Config.Internal.ResignQ
			if q == nil {
				return
			}
			select {
			case q <- tdns.ResignRequest{Zd: zd, Reason: tdns.ResignPeriodic}:
			case <-time.After(5 * time.Second):
				lg.Error("timeout registering zone for periodic re-signing", "zone", zd.ZoneName)
			}
		})
	}
}
