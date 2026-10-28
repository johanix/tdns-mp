/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * tdns-mp Config: wraps a pointer to tdns.Config, adds MP-specific state.
 * MainInit and StartMPSigner are receiver methods on this type.
 */
package tdnsmp

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Config wraps a pointer to the tdns.Config (typically &tdns.Conf)
// and adds MP-specific configuration and internal state.
//
// Using a pointer ensures that tdns code accessing the global
// tdns.Conf sees the same state as tdns-mp code.
type Config struct {
	*tdns.Config
	InternalMp InternalMpConf
}

// MpConfig returns the tdns-mp-side parse of the multi-provider
// config. This is the runtime source of truth for all MP config
// accessors. Returns nil if no multi-provider: block is present in
// the config (or if ParseConfig has not yet run).
func (conf *Config) MpConfig() *MultiProviderConf {
	return conf.InternalMp.mpConfig.Load()
}

// SetMpConfig installs the tdns-mp-side parse as the runtime MP config
// and mirrors it into the package-level WiredMpConfig(). The config
// parser hook calls it on every ParseConfig, including reloads, while
// the refresh callbacks read MpConfig() concurrently; the atomic pointer
// is what keeps that from being a data race.
func (conf *Config) SetMpConfig(mp *MultiProviderConf) {
	conf.InternalMp.mpConfig.Store(mp)
	wiredMpConfig.Store(mp)
}

// RegisterMPRefreshCallbacks appends tdns-mp PreRefresh/PostRefresh
// closures to all MP zones that don't already have them. Called at
// startup and after every zone reload (SIGHUP / "config reload-zones")
// via the PostParseZonesHook.
func (conf *Config) RegisterMPRefreshCallbacks() {
	tm := conf.InternalMp.MPTransport
	msgQs := conf.InternalMp.MsgQs
	if conf.InternalMp.refreshRegistered == nil {
		conf.InternalMp.refreshRegistered = make(map[string]bool)
	}
	// A zone that leaves the configuration takes its serials with it
	// (design rule 3): at the start, and after every zone reload, which
	// has removed it from tdns's zones by now.
	conf.InternalMp.Instructions.Prune(func(zone string) bool {
		zd, ok := tdns.Zones.Get(zone)
		return ok && zd.Options[tdns.OptMultiProvider]
	})
	for _, zoneName := range conf.InternalMp.MPZoneNames {
		if conf.InternalMp.refreshRegistered[zoneName] {
			continue
		}
		zd, ok := Zones.Get(zoneName)
		if !ok || !zd.Options[tdns.OptMultiProvider] {
			continue
		}
		// Wire SyncQ on every MP zone so PostRefresh can send without blocking
		if zd.SyncQ == nil {
			zd.SyncQ = conf.InternalMp.SyncQ
		}
		conf.InternalMp.refreshRegistered[zoneName] = true
		// The closure looks up conf.MpConfig() at invocation rather than
		// capturing the current pointer, so PostParseConfigHook can
		// replace the parsed MultiProviderConf on reload (SIGHUP) without
		// leaving these callbacks pointing at a stale copy.
		zd.OnZonePreRefresh = append(zd.OnZonePreRefresh,
			func(zd, new_zd *tdns.ZoneData) {
				if mpzd, ok := Zones.Get(zd.ZoneName); ok {
					mpzd.MPPreRefresh(new_zd, tm, msgQs, conf.MpConfig())
				}
			})
		zd.OnZonePostRefresh = append(zd.OnZonePostRefresh,
			func(zd *tdns.ZoneData) {
				if mpzd, ok := Zones.Get(zd.ZoneName); ok {
					// The copy is noted first: every reader after it acts
					// by the active instructions (plan S3).
					conf.noteInstructions(mpzd)
					givenBack := conf.onSetsChanged(mpzd, false)
					mpzd.PostRefresh(tm, msgQs)
					conf.afterSigningSetChange(mpzd)
					if givenBack {
						// after PostRefresh, which applies this refresh's
						// HSYNC3 change and recomputes the groups: who leads
						// is judged on the groups that change gives. (An
						// edit that also removes this agent's own HSYNC3
						// recomputes nothing, and is judged on the old ones.)
						conf.delegationSyncGivenBack(mpzd.ZoneName)
					}
				}
			})
	}
}

// ForEachMPZone iterates all zones with OptMultiProvider and calls
// the supplied function for each. Used as the "second-pass loop"
// for attaching OnFirstLoad callbacks, populating MPdata, and
// other MP-specific per-zone setup after ParseZones returns.
//
// Caller must ensure ParseZones has completed (i.e. call after
// conf.Config.MainInit returns). OnFirstLoad callbacks attached
// here will fire later when RefreshEngine processes initial loads.
func (conf *Config) ForEachMPZone(fn func(zd *MPZoneData)) {
	for _, zoneName := range conf.InternalMp.MPZoneNames {
		zd, exists := Zones.Get(zoneName)
		if !exists {
			continue
		}
		if !zd.Options[tdns.OptMultiProvider] {
			continue
		}
		fn(zd)
	}
}

// RegisterCombinerOnFirstLoad restores the persisted contributions of the
// MP zones that have not had them (and the PersistContributions callback),
// and attaches their OnFirstLoad callbacks (the combine, signal keys).
// Called at startup, before the refresh engine and the message router
// start, and on reload via PostParseZonesHook for mpcombiner.
//
// The contributions are restored here, before the zone's first load, and
// not in OnFirstLoad: the first load combines and publishes in
// MPPreRefresh, before the OnFirstLoad callbacks run, and the copy it
// publishes is the first one the signer is sent. Restored after it, that
// copy was the upstream's alone, without the other providers' DNSKEYs
// (tdns-mp #207).
func (conf *Config) RegisterCombinerOnFirstLoad() {
	hdb := NewHsyncDB(conf.Config.Internal.KeyDB)
	if hdb == nil {
		return
	}
	if conf.InternalMp.onFirstLoadRegistered == nil {
		conf.InternalMp.onFirstLoadRegistered = make(map[string]bool)
	}
	for _, zone := range providerZonesWithoutOption(conf.InternalMp.MPZoneNames) {
		lgCombiner.Warn("a provider zone lacks the multi-provider option: its _signal KEYs are not put back at a restart or a refresh, and a withdrawal from it waits for good",
			"zone", zone)
	}

	// Load contributions snapshot once for all new zones
	allContribs, err := LoadAllContributions(hdb)
	if err != nil {
		lgCombiner.Error("RegisterCombinerOnFirstLoad: failed to load contributions", "err", err)
		allContribs = nil
	}
	// And the stored publish instructions, to find the zones whose at-ns
	// publication is to be checked against the customer's consent. When
	// they cannot be read now, each zone reads them at its first load: the
	// provider zones' re-apply reads them for itself by then, and a KEY it
	// puts back has to meet the check all the same.
	allInstr, instrErr := LoadAllPublishInstructions(hdb)
	if instrErr != nil {
		lgCombiner.Error("RegisterCombinerOnFirstLoad: failed to load publish instructions; each zone reads them at its first load", "err", instrErr)
		allInstr = nil
	}

	for _, zoneName := range conf.InternalMp.MPZoneNames {
		if conf.InternalMp.onFirstLoadRegistered[zoneName] {
			continue
		}
		mpzd, exists := Zones.Get(zoneName)
		if !exists {
			continue
		}
		conf.InternalMp.onFirstLoadRegistered[zoneName] = true
		mpzd.restoreContributions(hdb, allContribs[zoneName], err == nil)

		mpzd.OnFirstLoad = append(mpzd.OnFirstLoad, func(zd *tdns.ZoneData) {
			if !zd.Options[tdns.OptMultiProvider] {
				return
			}
			// mpzd is the captured outer loop variable and is the
			// authoritative wrapper for this zone; no need to re-lookup.
			w := mpzd
			w.Lock()
			w.EnsureMP()
			doCombine := w.MPOptions[tdns.OptAllowEdits]
			w.Unlock()
			// The first-load combine in MPPreRefresh published the restored
			// contributions already; this one normally finds them in place.
			// CombineWithLocalChanges takes its own locks.
			if doCombine {
				success, err := w.CombineWithLocalChanges()
				if err != nil {
					lgCombiner.Error("CombineWithLocalChanges failed in OnFirstLoad", "zone", zd.ZoneName, "err", err)
				} else if success {
					lgCombiner.Info("applied local changes after the first load", "zone", zd.ZoneName)
				}
			}
		})

		if GetProviderZoneRRtypes(zoneName) != nil {
			mpzd.OnFirstLoad = append(mpzd.OnFirstLoad, func(zd *tdns.ZoneData) {
				if w, ok := Zones.Get(zd.ZoneName); ok {
					w.ApplyPendingSignalKeys(hdb)
				}
			})
		}

		// A zone with a stored at-ns instruction: once it has loaded, its
		// HSYNCPARAM can be read, and the instruction is checked against the
		// customer's consent. The provider zones' re-apply asks the same, but
		// may have run before this zone could answer.
		atNSSenders := atNSSendersOf(allInstr[zoneName])
		if len(atNSSenders) > 0 || instrErr != nil {
			mpzd.OnFirstLoad = append(mpzd.OnFirstLoad, func(zd *tdns.ZoneData) {
				w, ok := Zones.Get(zd.ZoneName)
				if !ok {
					return
				}
				senders := atNSSenders
				if instrErr != nil {
					instr, err := LoadAllPublishInstructions(hdb)
					if err != nil {
						lgCombiner.Error("failed to load publish instructions; the zone's at-ns publication is not checked against the customer's consent",
							"zone", zd.ZoneName, "err", err)
						return
					}
					senders = atNSSendersOf(instr[zd.ZoneName])
				}
				for _, senderID := range senders {
					w.withdrawSignalKeysWithoutConsent(senderID, zd.ZoneName, hdb)
				}
			})
		}
	}
}

// providerZonesWithoutOption is the configured provider zones that are not
// among the multi-provider zones. Everything the combiner does for a
// provider zone at a start and a refresh is attached to its multi-provider
// zones only (this function's caller and RegisterMPRefreshCallbacks), so
// such a zone is published to by the next instruction and loses the names
// again at the next restart or refresh.
func providerZonesWithoutOption(mpZoneNames []string) []string {
	mp := map[string]bool{}
	for _, z := range mpZoneNames {
		mp[dns.Fqdn(z)] = true
	}
	var missing []string
	for zone := range providerZoneRRtypes {
		if !mp[zone] {
			missing = append(missing, zone)
		}
	}
	sort.Strings(missing)
	return missing
}

// atNSSendersOf is the senders among a zone's stored publish instructions
// that ask for the at-ns location.
func atNSSendersOf(stored map[string]*StoredPublishInstruction) []string {
	var senders []string
	for senderID, instr := range stored {
		if containsString(instr.Locations, "at-ns") {
			senders = append(senders, senderID)
		}
	}
	return senders
}

// restoreContributions sets the zone's PersistContributions callback and
// puts its persisted contributions back in AgentContributions, before
// anything is combined for the zone (RegisterCombinerOnFirstLoad).
// zoneContribs is the zone's part of the snapshot, nil when it has none.
// read says that the snapshot was read without an error: only then is the
// zone's store read (ContributionsRead), also when it holds nothing.
func (mpzd *MPZoneData) restoreContributions(hdb *HsyncDB, zoneContribs map[string]map[string]map[uint16]core.RRset, read bool) {
	mpzd.Lock()
	defer mpzd.Unlock()
	mpzd.EnsureMP()
	if mpzd.MP.PersistContributions == nil {
		mpzd.MP.PersistContributions = func(zone, senderID string, contribs map[string]map[uint16]core.RRset) error {
			return SaveContributions(hdb, zone, senderID, contribs)
		}
	}
	if read {
		mpzd.MP.ContributionsRead = true
	}
	if mpzd.MP.AgentContributions != nil || len(zoneContribs) == 0 {
		return
	}
	mpzd.MP.AgentContributions = make(map[string]map[string]map[uint16]core.RRset, len(zoneContribs))
	for senderID, ownerMap := range zoneContribs {
		mpzd.MP.AgentContributions[senderID] = ownerMap
	}
	mpzd.RebuildCombinerData()
	lgCombiner.Info("restored the persisted contributions before the first load",
		"zone", mpzd.ZoneName, "agents", len(zoneContribs))
}

// InternalMpConf holds multi-provider internal state local to
// tdns-mp. Mirrors tdns.InternalMpConf field-by-field. During
// migration, both exist — code in tdns-mp reads from here,
// code in tdns reads from tdns.Config.Internal.
type InternalMpConf struct {
	// IdentityReady opens once the agent's identity zone is published; the
	// sync engine's first hello waits on it (agent_identity_ready.go).
	IdentityReady         *identityReadiness
	KeyLifecycle          *KeyLifecycleEngine
	KeyLifecycleOwner     *MPKeyLifecycleOwner
	HsyncDB               *HsyncDB
	Instructions          *InstructionStore // the zones' serials, on the agent and the auditor
	SyncQ                 chan SyncRequest
	MsgQs                 *MsgQs
	SyncStatusQ           chan SyncStatus
	AgentRegistry         *AgentRegistry
	ZoneDataRepo          *ZoneDataRepo
	CombinerState         *CombinerState
	TransportManager      *transport.TransportManager
	MPTransport           *MPTransportBridge
	LeaderElectionManager *LeaderElectionManager
	MPZoneNames           []string
	DistributionCache     *DistributionCache
	AuditStateManager     *AuditStateManager
	AuditWebAuth          *AuditWebAuth
	refreshRegistered     map[string]bool // tracks which zones have tdns-mp refresh callbacks
	onFirstLoadRegistered map[string]bool // tracks which zones have combiner OnFirstLoad callbacks

	// mpConfig is the tdns-mp-side parse of the multi-provider: config
	// block, installed by SetMpConfig from the config parser hook
	// (RegisterMpConfigParser) on every parse. Read through
	// conf.MpConfig(); an atomic pointer because reloads store it while
	// runtime goroutines read it.
	mpConfig atomic.Pointer[MultiProviderConf]

	// delegationSyncChains: the zones whose last delegation sync failed, or
	// went to the parent as a NOTIFY, and how often, for the asks that
	// follow, and what is scheduled for them (mp_s5_leader_sync.go)
	delegationSyncChains delegationSyncChains
	// keyLogs: when the key rounds' lines were last logged (step 7b, the
	// first time and then once an hour).
	keyLogs hourlyLog
	// keyPoll stands in for tdns's poll of the parent for a zone's SIG(0)
	// key in a test (ParentSyncAfterKeyPublication). Nil runs tdns's.
	keyPoll func(ctx context.Context, zone ZoneName, keyName string, keyid uint16, algorithm uint8)
	// keyPolls: per zone, the polls of the zone's SIG(0) key with its parent
	// that run in this process, and what the hold of the leader's sync for
	// the key needs besides (step 7b, key_hold.go).
	keyPolls keyPollBook
	// ownReads counts the re-reads of the agents' own state under way
	// (own_read.go), until each has handed its answer back.
	ownReads sync.WaitGroup
	// editsRequest stands in for requestEdits, the own read's request to the
	// combiner, in a test.
	editsRequest func(ctx context.Context, zd *tdns.ZoneData, tm *MPTransportBridge, msgQs *MsgQs) (*EditsResponseMsg, time.Time, error)
	// CatchUp is the agent's catch-up tracker (catchup.go); nil on every
	// other role.
	CatchUp *catchUpTracker
}
