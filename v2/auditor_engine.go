/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdnsmp

import (
	"context"
	"fmt"
	"slices"
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
	msgQs        *MsgQs      // set by Run; carries the final confirmation back to a distribution's originator
	keyStates    keyStateHistory
}

func NewAuditorEngine(conf *Config, stateManager *AuditStateManager) *AuditorEngine {
	engine := newAuditorHsyncEngine(conf)
	if ar := conf.InternalMp.AgentRegistry; ar != nil {
		ar.HsyncEngine = engine
		ar.Registry = engine.Registry() // A3d.1: embed the engine's single peer map
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
	e.msgQs = msgQs
	e.core.SetHandler(e.onInboundMsg)

	ar := e.conf.InternalMp.AgentRegistry
	helloCh := adaptHelloReports(ctx, msgQs.Hello, e.stateManager, e.auditLog, ar)
	beatCh := adaptBeatReports(ctx, msgQs.Beat, e.stateManager, ar)
	// The first beat rounds come within seconds of the start; this process's
	// first gossip rows wait until they carry good news, or one beat interval.
	holdFirstLocalRows(ar, hsyncConfigFromMp(e.conf.MpConfig()).BeatInterval)

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
			Details:     msg.Describe(),
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
		// The sender's role comes from the zone, as a beat's does, not
		// from whether a beat has arrived yet: a DNSKEY sync can precede
		// the sender's first beat for the zone (#108). Until the zone's
		// roles are known there is nothing to judge the sync by.
		if label, isSigner, known := zoneMemberRole(msg.Zone, senderID); known {
			zs.NoteProviderRole(senderID, label, isSigner)
			detectMsgObservations(zs, senderID, msg, rrtypes)
		}
	}

	// The row's other columns already say the type, the sender and the
	// counts: its summary says what the message carries. The details show
	// each key against what the sender said about it last time.
	prev := e.keyStates.next(zone, senderID, msg.Operations)
	logEvent(e.auditLog, &AuditEvent{
		Time:        time.Now(),
		Zone:        zone,
		Originator:  senderID,
		DeliveredBy: deliveredBy,
		EventType:   string(msg.MessageType),
		Summary:     msg.Summary(),
		RRsAdded:    added,
		RRsRemoved:  removed,
		RRtypes:     strings.Join(rrtypes, ","),
		Details:     msg.DescribeSince(prev),
	})
	// The event logged, the auditor's task is done: its final word to the
	// originator (#101).
	auditorConfirms(e.msgQs, msg, senderID, zone)
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
				Details: confirm.Describe(),
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
					Details:    report.Describe(),
				})
				select {
				case out <- &hsync.InboundReport{
					Transport:   report.Transport,
					MessageType: hsync.AgentMsg(report.MessageType),
					Zone:        hsync.ZoneName(report.Zone),
					Identity:    hsync.PeerID(report.Identity),
					Msg:         report.Msg,
				}:
				case <-ctx.Done():
					// the consumer (hsync.Engine.Run) has stopped reading
					return
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
		gossipState = AgentStateToString[ar.effectiveAgentState(agent.ID)]
	}
	label, isSigner, _ = zoneMemberRole(zone, identity)
	return label, gossipState, isSigner
}

// zoneMemberRole resolves identity's role in zone from the zone's apex as
// the auditor has it: its HSYNC3 label, and whether HSYNCPARAM lists any of
// its labels under signers=. known is false while the zone is not loaded and
// Ready at the auditor, or identity is not an HSYNC3 member of it: there is
// then no role to judge by, and label and isSigner say nothing. A beat and a
// sync resolve their sender's role the same way (#108).
func zoneMemberRole(zone ZoneName, identity string) (label string, isSigner, known bool) {
	if zone == "" {
		return "", false, false
	}
	zd, exists := Zones.Get(dns.Fqdn(string(zone)))
	if !exists || !zd.Ready {
		return "", false, false
	}
	// Resolve the labels the way the zone view does (hsync3IdentitiesByLabel):
	// inactive members included, identities compared as FQDNs. An identity
	// may hold several labels, one agent serving as two providers: it signs
	// if any of them is a signer, and the label recorded is the first in
	// sorted order, not whichever a walk over the map meets first.
	want := dns.Fqdn(identity)
	var labels []string
	for lbl, id := range zd.hsync3IdentitiesByLabel() {
		if id == want {
			labels = append(labels, lbl)
		}
	}
	if len(labels) == 0 {
		return "", false, false
	}
	slices.Sort(labels)
	label = labels[0]
	// A member is a signer only when listed under signers=; a servers=
	// member serves the zone without signing it. Without an HSYNCPARAM the
	// zone declares no roles at all.
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		return label, false, false
	}
	hpRRset, ok := apex.RRtypes.Get(core.TypeHSYNCPARAM)
	if !ok || len(hpRRset.RRs) == 0 {
		return label, false, false
	}
	prr, ok := hpRRset.RRs[0].(*dns.PrivateRR)
	if !ok {
		return label, false, false
	}
	hp, ok := prr.Data.(*core.HSYNCPARAM)
	if !ok {
		return label, false, false
	}
	for _, l := range hp.GetSigners() {
		if slices.Contains(labels, normalizeHSYNC3Label(l)) {
			isSigner = true
			break
		}
	}
	return label, isSigner, true
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
						gossip[i] = abp.Gossip[i]
					}
					msg = &hsync.BeatPost{
						MessageType: hsync.MsgBeat,
						Gossip:      gossip,
					}
				}
				select {
				case out <- &hsync.InboundReport{
					Transport:    report.Transport,
					MessageType:  hsync.MsgBeat,
					Zone:         hsync.ZoneName(report.Zone),
					Identity:     hsync.PeerID(report.Identity),
					BeatInterval: report.BeatInterval,
					Msg:          msg,
				}:
				case <-ctx.Done():
					return
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
				select {
				case out <- &hsync.InboundMsg{
					MessageType: hsync.AgentMsg(msg.MessageType),
					Originator:  hsync.PeerID(msg.OriginatorID),
					Zone:        hsync.ZoneName(msg.Zone),
					Payload:     msg,
				}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}
