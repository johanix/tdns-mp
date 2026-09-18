/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"

	"github.com/johanix/tdns-mp/v2/hsync"
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
	changed, ds, err := zd.LocalDnskeysFromKeystate()
	if err != nil || !changed {
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
		},
	}, synchedDataUpdateQ, msgQs)
}
