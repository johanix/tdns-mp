/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	tdns "github.com/johanix/tdns/v2"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// AuditorEngine composes hsync.Engine with auditor-specific observation.
type AuditorEngine struct {
	core         *hsync.Engine
	conf         *Config
	stateManager *AuditStateManager
	auditLog     *tdns.KeyDB // optional persistent log
}

func NewAuditorEngine(conf *Config, stateManager *AuditStateManager) *AuditorEngine {
	engine := newAuditorHsyncEngine(conf)
	if ar := conf.InternalMp.AgentRegistry; ar != nil {
		ar.HsyncEngine = engine
	}
	return &AuditorEngine{
		core:         engine,
		conf:         conf,
		stateManager: stateManager,
		auditLog:     conf.Config.Internal.KeyDB,
	}
}

// Run starts the shared protocol loop and audit-side MsgQ consumers.
func (e *AuditorEngine) Run(ctx context.Context, msgQs *MsgQs) {
	if e == nil || e.core == nil || msgQs == nil {
		return
	}
	e.core.SetSyncHandler(e.onInboundMsg)
	e.core.SetElectionHandler(e.onInboundMsg)

	ar := e.conf.InternalMp.AgentRegistry
	helloCh := adaptHelloReports(ctx, msgQs.Hello, e.stateManager, e.auditLog, ar)
	beatCh := adaptBeatReports(ctx, msgQs.Beat, e.stateManager, ar)

	go e.core.Run(ctx, hsync.MsgChannels{
		Hello: helloCh,
		Beat:  beatCh,
		Msg:   adaptInboundMsgs(ctx, msgQs.Msg),
	})

	e.runAux(ctx, msgQs)
}

func (e *AuditorEngine) onInboundMsg(msg *hsync.InboundMsg) {
	if msg == nil {
		return
	}
	amp := &AgentMsgPostPlus{
		AgentMsgPost: AgentMsgPost{
			MessageType:  AgentMsg(msg.MessageType),
			OriginatorID: AgentId(msg.Originator),
			Zone:         ZoneName(msg.Zone),
		},
	}
	if payload, ok := msg.Payload.(*AgentMsgPostPlus); ok {
		amp = payload
	}
	e.recordSyncMsg(amp)
}

func (e *AuditorEngine) recordSyncMsg(msg *AgentMsgPostPlus) {
	if msg == nil {
		return
	}
	senderID := string(msg.OriginatorID)
	deliveredBy := string(msg.DeliveredBy)
	if deliveredBy == "" {
		deliveredBy = senderID
	}
	zone := string(msg.Zone)

	if msg.MessageType == AgentMsgRfi {
		switch msg.RfiType {
		case "ELECT-CALL":
			lgAuditor.Info("leader election initiated",
				"group_or_zone", zone, "initiator", senderID)
		default:
			lgAuditor.Debug("RFI received", "type", msg.RfiType, "sender", senderID, "zone", zone)
		}
		logEvent(e.auditLog, &AuditEvent{
			Time:        time.Now(),
			Zone:        zone,
			Originator:  senderID,
			DeliveredBy: deliveredBy,
			EventType:   "rfi",
			Summary:     fmt.Sprintf("RFI %s from %s", msg.RfiType, senderID),
		})
		return
	}

	added, removed, rrtypes, contributions := summarizeMsgRecords(msg)
	lgAuditor.Info("sync/update received",
		"sender", senderID, "deliveredBy", deliveredBy,
		"zone", zone, "msgType", msg.MessageType,
		"added", added, "removed", removed)

	if e.stateManager != nil && zone != "" && IsProviderIdentity(zone, senderID) {
		zs := e.stateManager.GetOrCreateZone(zone)
		zs.UpdateProviderSync(senderID, contributions)
		detectMsgObservations(zs, senderID, msg, rrtypes)
	}

	logEvent(e.auditLog, &AuditEvent{
		Time:        time.Now(),
		Zone:        zone,
		Originator:  senderID,
		DeliveredBy: deliveredBy,
		EventType:   string(msg.MessageType),
		Summary:     fmt.Sprintf("%s from %s: +%d/-%d RRs", msg.MessageType, senderID, added, removed),
		RRsAdded:    added,
		RRsRemoved:  removed,
		RRtypes:     strings.Join(rrtypes, ","),
	})
}

func (e *AuditorEngine) runAux(ctx context.Context, msgQs *MsgQs) {
	for {
		select {
		case <-ctx.Done():
			return
		case report := <-msgQs.Ping:
			if report != nil {
				lgAuditor.Debug("ping received", "sender", string(report.Identity))
			}
		case confirm := <-msgQs.Confirmation:
			if confirm == nil {
				continue
			}
			logEvent(e.auditLog, &AuditEvent{
				Time:       time.Now(),
				Zone:       string(confirm.Zone),
				Originator: confirm.Source,
				EventType:  "confirm",
				Summary: fmt.Sprintf("CONFIRM %s from %s (distrib %s)",
					confirm.Status, confirm.Source, confirm.DistributionID),
			})
		case statusMsg := <-msgQs.StatusUpdate:
			if statusMsg != nil {
				lgAuditor.Debug("status-update received",
					"zone", statusMsg.Zone, "subtype", statusMsg.SubType, "sender", statusMsg.SenderID)
			}
		}
	}
}

func adaptHelloReports(ctx context.Context, in <-chan *AgentMsgReport,
	sm *AuditStateManager, kdb *tdns.KeyDB, ar *AgentRegistry) <-chan *hsync.InboundReport {
	out := make(chan *hsync.InboundReport)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case report, ok := <-in:
				if !ok {
					return
				}
				if report == nil {
					continue
				}
				senderID := string(report.Identity)
				zone := string(report.Zone)
				lgAuditor.Info("hello received", "sender", senderID, "zone", zone)
				if ar != nil {
					ar.HelloHandler(report)
				}
				logEvent(kdb, &AuditEvent{
					Time:       time.Now(),
					Zone:       zone,
					Originator: senderID,
					EventType:  "hello",
					Summary:    fmt.Sprintf("HELLO from %s", senderID),
				})
				out <- &hsync.InboundReport{
					Transport:   report.Transport,
					MessageType: hsync.AgentMsg(report.MessageType),
					Zone:        hsync.ZoneName(report.Zone),
					Identity:    hsync.PeerID(report.Identity),
					Msg:         report.Msg,
				}
			}
		}
	}()
	return out
}

func providerBeatMeta(ar *AgentRegistry, zone ZoneName, identity string) (label, gossipState string, isSigner bool) {
	if ar == nil {
		return "", "", false
	}
	if agent, ok := ar.S.Get(AgentId(identity)); ok {
		gossipState = AgentStateToString[agent.EffectiveState()]
	}
	if zone == "" {
		return label, gossipState, isSigner
	}
	zd, exists := Zones.Get(string(zone))
	if !exists || !zd.Ready {
		return label, gossipState, isSigner
	}
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return label, gossipState, isSigner
	}
	hsyncRRset := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNC3)
	if len(hsyncRRset.RRs) == 0 {
		return label, gossipState, isSigner
	}
	labelToIdentity := map[string]string{}
	for _, rr := range hsyncRRset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		h3, ok := prr.Data.(*core.HSYNC3)
		if !ok || h3.State == 0 {
			continue
		}
		labelToIdentity[strings.TrimSuffix(h3.Label, ".")] = h3.Identity
		if h3.Identity == identity {
			label = strings.TrimSuffix(h3.Label, ".")
		}
	}
	if hpRRset, ok := apex.RRtypes.Get(core.TypeHSYNCPARAM); ok && len(hpRRset.RRs) > 0 {
		if prr, ok := hpRRset.RRs[0].(*dns.PrivateRR); ok {
			if hp, ok := prr.Data.(*core.HSYNCPARAM); ok {
				for _, l := range append(hp.GetSigners(), hp.GetServers()...) {
					key := strings.TrimSuffix(l, ".")
					if id, ok := labelToIdentity[key]; ok && id == identity {
						isSigner = true
						break
					}
				}
			}
		}
	}
	return label, gossipState, isSigner
}

func adaptBeatReports(ctx context.Context, in <-chan *AgentMsgReport,
	sm *AuditStateManager, ar *AgentRegistry) <-chan *hsync.InboundReport {
	out := make(chan *hsync.InboundReport)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case report, ok := <-in:
				if !ok {
					return
				}
				if report == nil {
					continue
				}
				if ar != nil {
					ar.HeartbeatHandler(report)
				}
				if sm != nil && report.Zone != "" {
					zone := string(report.Zone)
					identity := string(report.Identity)
					label, gossipState, isSigner := providerBeatMeta(ar, report.Zone, identity)
					zs := sm.GetOrCreateZone(zone)
					if IsAuditorIdentity(zone, identity) {
						zs.UpdateAuditorBeat(identity, label, gossipState)
					} else if IsProviderIdentity(zone, identity) {
						zs.UpdateProviderBeat(identity, label, gossipState, isSigner)
					}
				}
				var msg interface{}
				if abp, ok := report.Msg.(*AgentBeatPost); ok {
					gossip := make([]hsync.GossipMessage, len(abp.Gossip))
					for i := range abp.Gossip {
						gossip[i] = gossipMessageToHsync(&abp.Gossip[i])
					}
					msg = &hsync.BeatPost{
						MessageType: hsync.MsgBeat,
						Gossip:      gossip,
					}
				}
				out <- &hsync.InboundReport{
					Transport:    report.Transport,
					MessageType:  hsync.MsgBeat,
					Zone:         hsync.ZoneName(report.Zone),
					Identity:     hsync.PeerID(report.Identity),
					BeatInterval: report.BeatInterval,
					Msg:          msg,
				}
			}
		}
	}()
	return out
}

func adaptInboundMsgs(ctx context.Context, in <-chan *AgentMsgPostPlus) <-chan *hsync.InboundMsg {
	out := make(chan *hsync.InboundMsg)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-in:
				if !ok {
					return
				}
				if msg == nil {
					continue
				}
				out <- &hsync.InboundMsg{
					MessageType: hsync.AgentMsg(msg.MessageType),
					Originator:  hsync.PeerID(msg.OriginatorID),
					Zone:        hsync.ZoneName(msg.Zone),
					Payload:     msg,
				}
			}
		}
	}()
	return out
}

func gossipMessageToHsync(m *GossipMessage) hsync.GossipMessage {
	if m == nil {
		return hsync.GossipMessage{}
	}
	out := hsync.GossipMessage{
		GroupHash: m.GroupHash,
		GroupName: hsync.GroupNameProposal{
			GroupHash:  m.GroupName.GroupHash,
			Name:       m.GroupName.Name,
			Proposer:   m.GroupName.Proposer,
			ProposedAt: m.GroupName.ProposedAt,
		},
		Election: hsync.GroupElectionState{
			Leader:       m.Election.Leader,
			Term:         m.Election.Term,
			LeaderExpiry: m.Election.LeaderExpiry,
		},
		Members: make(map[string]*hsync.MemberState, len(m.Members)),
	}
	for id, ms := range m.Members {
		if ms == nil {
			continue
		}
		out.Members[id] = &hsync.MemberState{
			Identity:     ms.Identity,
			PeerStates:   ms.PeerStates,
			Zones:        ms.Zones,
			Timestamp:    ms.Timestamp,
			BeatInterval: ms.BeatInterval,
		}
	}
	return out
}
