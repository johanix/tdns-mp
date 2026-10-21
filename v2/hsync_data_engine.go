/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"slices"

	"github.com/johanix/tdns-mp/v2/hsync"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

// HsyncDataEngine is the agent-only shell around hsync.Engine (SDE feeding,
// keystate inventory, delegation sync triggers, election participation).
type HsyncDataEngine struct {
	core *hsync.Engine
	conf *Config
}

// NewHsyncDataEngine constructs the agent data engine. Not wired until Phase 5.
func NewHsyncDataEngine(conf *Config) *HsyncDataEngine {
	engine := newAgentHsyncEngine(conf)
	if ar := conf.InternalMp.AgentRegistry; ar != nil {
		ar.HsyncEngine = engine
		ar.Registry = engine.Registry() // A3d.1: embed the engine's single peer map
	}
	return &HsyncDataEngine{core: engine, conf: conf}
}

// Run starts the shared protocol engine and agent-only MsgQ work.
func (e *HsyncDataEngine) Run(ctx context.Context, msgQs *MsgQs) {
	if e == nil || e.core == nil || msgQs == nil {
		return
	}
	e.core.SetHandler(e.onSyncMessage)

	ar := e.conf.InternalMp.AgentRegistry
	helloCh := adaptHelloReports(ctx, msgQs.Hello, nil, nil, ar)
	beatCh := adaptBeatReports(ctx, msgQs.Beat, nil, ar)
	// The first beat rounds come within seconds of the start; this process's
	// first gossip rows wait until they carry good news, or one beat interval.
	holdFirstLocalRows(ar, hsyncConfigFromMp(e.conf.MpConfig()).BeatInterval)

	go e.core.Run(ctx, hsync.MsgChannels{
		Hello: helloCh,
		Beat:  beatCh,
		Msg:   adaptInboundMsgs(ctx, msgQs.Msg),
	})

	e.runAgentOnly(ctx, msgQs)
}

func (e *HsyncDataEngine) onSyncMessage(msg *hsync.InboundMsg) {
	if msg == nil {
		return
	}
	if amp, ok := msg.Payload.(*AgentMsgPostPlus); ok {
		registry := e.conf.InternalMp.AgentRegistry
		registry.MsgHandler(amp, msgQsSynchedDataUpdate(e.conf), e.conf.InternalMp.MsgQs.SynchedDataCmd)
	}
}

func msgQsSynchedDataUpdate(conf *Config) chan *SynchedDataUpdate {
	if conf.InternalMp.MsgQs != nil {
		return conf.InternalMp.MsgQs.SynchedDataUpdate
	}
	return nil
}

func (e *HsyncDataEngine) runAgentOnly(ctx context.Context, msgQs *MsgQs) {
	ourID := AgentId(e.conf.MpConfig().Identity)
	registry := e.conf.InternalMp.AgentRegistry
	syncQ := e.conf.InternalMp.SyncQ
	synchedDataUpdateQ := msgQs.SynchedDataUpdate
	e.conf.InternalMp.SyncStatusQ = make(chan SyncStatus, 10)

	for {
		select {
		case <-ctx.Done():
			return
		case syncitem := <-syncQ:
			registry.SyncRequestHandler(ourID, syncitem, synchedDataUpdateQ, msgQs)
		case mgmtPost := <-msgQs.Command:
			registry.CommandHandler(mgmtPost, synchedDataUpdateQ, msgQs)
		case mgmtPost := <-msgQs.DebugCommand:
			registry.CommandHandler(mgmtPost, synchedDataUpdateQ, msgQs)
		case req := <-e.conf.InternalMp.SyncStatusQ:
			registry.HandleStatusRequest(req)
		case statusMsg := <-msgQs.StatusUpdate:
			e.handleStatusUpdate(ctx, statusMsg)
		case inventoryMsg := <-msgQs.KeystateInventory:
			e.handleKeystateInventory(ctx, ourID, inventoryMsg, synchedDataUpdateQ, msgQs)
		}
	}
}

func (e *HsyncDataEngine) handleStatusUpdate(ctx context.Context, statusMsg *StatusUpdateMsg) {
	if statusMsg == nil {
		return
	}
	switch statusMsg.SubType {
	case "ns-changed", "ksk-changed":
		// the combiner's hint that the delegation's data changed: the same
		// request, through the same gate (parentsync=agent, and this agent
		// leads), without waiting for room on the syncher's queue and
		// tried again if there was none
		e.conf.requestDelegationSync(ctx, statusMsg.Zone, "the combiner's "+statusMsg.SubType+" hint")
	}
}

func (e *HsyncDataEngine) handleKeystateInventory(ctx context.Context, ourID AgentId,
	inventoryMsg *KeystateInventoryMsg, synchedDataUpdateQ chan *SynchedDataUpdate, msgQs *MsgQs) {
	if inventoryMsg == nil {
		return
	}
	zd, exists := Zones.Get(inventoryMsg.Zone)
	if !exists {
		return
	}
	e.conf.noteKeyInventory(ctx, zd, inventoryMsg)
	changed, ds, err := zd.LocalDnskeysFromKeystate(ourID, nil)
	if err != nil {
		return
	}
	// The keys the signer sends again go to the peers again, tracked for
	// them, whether or not the key set changed: unmarked, an unchanged
	// inventory distributes nothing, and the key lifecycle's resend never
	// left this agent (#256).
	if resendKeys(ds, inventoryMsg.Resend, inventoryMsg.Inventory) {
		lgEngine.Info("the signer sends keys again: distributing them to the peers again", "zone", inventoryMsg.Zone, "keys", inventoryMsg.Resend)
		changed = true
	}
	if !changed {
		return
	}
	e.conf.InternalMp.AgentRegistry.SyncRequestHandler(ourID, SyncRequest{
		ZoneName: ZoneName(inventoryMsg.Zone),
		Command:  "SYNC-DNSKEY-RRSET",
		DnskeyStatus: &DnskeyStatus{
			Time:             ds.Time,
			ZoneName:         ds.ZoneName,
			LocalAdds:        ds.LocalAdds,
			LocalRemoves:     ds.LocalRemoves,
			CurrentLocalKeys: ds.CurrentLocalKeys,
			CurrentKeyStates: ds.CurrentKeyStates,
			StatesChanged:    ds.StatesChanged,
			Resend:           ds.Resend,

			ResendRemovedTags: ds.ResendRemovedTags,
		},
	}, synchedDataUpdateQ, msgQs)
}

// resendKeys adds to ds the keys whose distribution the signer's key
// lifecycle sends again (tags): a key this provider serves as an add, and
// one of its own it has withdrawn (mpremove, removed) as a removal, by its
// tag alone (ResendRemovedTags). Each is then a key the distribution is
// tracked for (DnskeyKeyTags), and ds is marked as a resend, which the data
// engine distributes even when its repo already holds the set. A tag that is
// neither, another provider's key among them, is not named. False when no
// key of tags is named.
func resendKeys(ds *DnskeyStatus, tags []uint16, inv []KeyInventoryItem) bool {
	if ds == nil || len(tags) == 0 {
		return false
	}
	find := func(rrs []dns.RR, tag uint16) dns.RR {
		for _, rr := range rrs {
			if k, ok := rr.(*dns.DNSKEY); ok && k.KeyTag() == tag {
				return rr
			}
		}
		return nil
	}
	named := false
	for _, tag := range tags {
		if find(ds.LocalAdds, tag) != nil || find(ds.LocalRemoves, tag) != nil || slices.Contains(ds.ResendRemovedTags, tag) {
			named = true // in this distribution already
			continue
		}
		if rr := find(ds.CurrentLocalKeys, tag); rr != nil {
			ds.LocalAdds = append(ds.LocalAdds, rr)
			named = true
			continue
		}
		withdrawn := slices.ContainsFunc(inv, func(it KeyInventoryItem) bool {
			return it.KeyTag == tag && (it.State == DnskeyStateMpremove || it.State == tdns.DnskeyStateRemoved)
		})
		if withdrawn {
			ds.ResendRemovedTags = append(ds.ResendRemovedTags, tag)
			named = true
		}
	}
	if named {
		ds.Resend = true
	}
	return named
}
