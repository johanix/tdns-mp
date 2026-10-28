/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Signer message handler goroutine.
 * Consumes beat, hello, ping, and RFI messages from MsgQs.
 * Handles RFI KEYSTATE by querying KeyDB and pushing a complete
 * KEYSTATE inventory back to the requesting agent, and the agent's
 * hand-over (KEYSTATE "acting", plan S11).
 */

package tdnsmp

import (
	"context"
	"fmt"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	tdns "github.com/johanix/tdns/v2"
	"github.com/miekg/dns"
)

var lgSigner = tdns.Logger("signer")

// SignerMsgHandler consumes beat, hello, ping, and RFI messages from MsgQs.
// Updates PeerRegistry liveness on beats and logs hello/ping messages.
// Processes RFI KEYSTATE requests by querying KeyDB and pushing inventory.
func SignerMsgHandler(ctx context.Context, conf *Config, msgQs *MsgQs) {
	if msgQs == nil {
		lgSigner.Warn("No MsgQs configured, exiting")
		return
	}

	tm := conf.InternalMp.MPTransport
	var peerRegistry *transport.PeerRegistry
	if tm != nil {
		peerRegistry = tm.PeerRegistry
	}

	lgSigner.Info("Starting", "peerRegistry", peerRegistry != nil)

	for {
		select {
		case <-ctx.Done():
			lgSigner.Info("Context cancelled, stopping")
			return

		case report := <-msgQs.Beat:
			if report == nil {
				continue
			}
			senderID := string(report.Identity)
			lgSigner.Debug("Beat received", "sender", senderID, "interval", report.BeatInterval, "distrib", report.DistributionID)

			// Record inbound liveness ONLY (a received beat proves they can
			// reach us, not that we can reach them — which is what
			// OPERATIONAL means). State is set on the outbound beat path.
			if peerRegistry != nil {
				peer := peerRegistry.GetOrCreate(senderID)
				peer.SetMechanismLastBeatRecv("DNS", time.Now())
			}

		case report := <-msgQs.Hello:
			if report == nil {
				continue
			}
			senderID := string(report.Identity)
			lgSigner.Debug("Hello received", "sender", senderID)

			// Inbound liveness only — a received hello does not assert
			// OPERATIONAL (that requires an outbound beat round-trip).
			if peerRegistry != nil {
				peer := peerRegistry.GetOrCreate(senderID)
				peer.SetLastBeatReceived(time.Now())
			}

		case report := <-msgQs.Ping:
			if report == nil {
				continue
			}
			lgSigner.Debug("Ping received", "sender", string(report.Identity), "distrib", report.DistributionID)

		case statusMsg := <-msgQs.StatusUpdate:
			if statusMsg == nil {
				continue
			}
			lgSigner.Info("STATUS-UPDATE received (no action on signer)", "zone", statusMsg.Zone, "subtype", statusMsg.SubType, "sender", statusMsg.SenderID)

		case sigMsg := <-msgQs.KeystateSignal:
			if sigMsg == nil {
				continue
			}
			lgSigner.Info("KEYSTATE signal received", "signal", sigMsg.Signal, "zone", sigMsg.Zone, "keyTag", sigMsg.KeyTag, "sender", sigMsg.SenderID)

			if sigMsg.SenderID == "" {
				lgSigner.Warn("KEYSTATE signal with empty sender, ignoring", "zone", sigMsg.Zone, "signal", sigMsg.Signal)
				continue
			}

			// the agent's hand-over (plan S11): what the signer acts by
			if sigMsg.Signal == "acting" {
				conf.signerTakeHandover(sigMsg)
				continue
			}

			// what the other providers said about their keys (#58), and
			// which providers have spoken (S7): the owner of the zone's key
			// lifecycle writes ds on their rows from it; for a zone nobody
			// here owns it has no reader
			if sigMsg.Signal == "foreign" {
				if e := conf.InternalMp.KeyLifecycle; e == nil || !e.ForeignWord(sigMsg.Zone, sigMsg.ForeignKeys, sigMsg.ForeignSpoken) {
					lgSigner.Debug("KEYSTATE foreign for a zone whose key lifecycle is not run here; dropped", "zone", sigMsg.Zone)
					continue
				}
				// a foreign DNSKEY an incoming zone lacked was kept until the
				// key states relayed for its provider, or the zone owner,
				// let it go; these key states may do that (#207)
				if mpzd, ok := Zones.Get(dns.Fqdn(sigMsg.Zone)); ok && mpzd.dropWithdrawnForeignDNSKEYs(conf.MpConfig()) {
					sendResignRequest(tdns.Conf.Internal.ResignQ, mpzd.ZoneName)
				}
				continue
			}

			// a zone tdns-mp's own state machine runs: the signal is its.
			// For any other zone the signal has no taker: tdns-mp's machine
			// is the only one that distributes keys to the peers (no hook
			// stages them through tdns since S4a), and a zone named in the
			// config but not taken yet is asked again by the resend timer
			// once its driver runs. Nothing is written to the keystore
			// behind the machine's back.
			if e := conf.InternalMp.KeyLifecycle; e != nil && e.Signal(sigMsg.Zone, sigMsg.KeyTag, sigMsg.Signal, sigMsg.Message, sigMsg.At) {
				continue
			}
			lgSigner.Info("KEYSTATE signal for a zone whose key lifecycle is not run here; dropped", "signal", sigMsg.Signal, "zone", sigMsg.Zone, "keyTag", sigMsg.KeyTag, "sender", sigMsg.SenderID)

		case msg := <-msgQs.Msg:
			if msg == nil {
				continue
			}
			senderID := string(msg.OriginatorID)
			if senderID == "" {
				senderID = string(msg.DeliveredBy) // Fallback to transport sender
			}
			zone := string(msg.Zone)
			rfiType := msg.RfiType

			lgSigner.Debug("RFI received", "type", rfiType, "sender", senderID, "zone", zone)

			switch rfiType {
			case "KEYSTATE":
				if err := sendKeystateInventoryToAgent(ctx, conf, tm, senderID, zone, nil); err != nil {
					lgSigner.Error("Failed to send KEYSTATE inventory", "agent", senderID, "zone", zone, "err", err)
				}
			default:
				lgSigner.Warn("Unknown RFI type, ignoring", "type", rfiType, "sender", senderID)
			}
		}
	}
}

// pushKeystateInventoryToAllAgents sends the current KEYSTATE inventory to all
// configured agents: the key machine's Distribute, DistributeRemoval and
// KeysChanged (every key row write, state or column), so the agents learn
// about the change and distribute it to the peers.
func pushKeystateInventoryToAllAgents(conf *Config, zone string) {
	pushKeystateInventory(conf, zone, nil)
}

// pushKeystateInventory is pushKeystateInventoryToAllAgents with the keys
// whose distribution the key lifecycle sends again marked (resend): the
// agents distribute those again even when nothing changed (#256).
func pushKeystateInventory(conf *Config, zone string, resend []uint16) {
	mp := conf.MpConfig()
	if mp == nil || len(mp.Agents) == 0 {
		return
	}
	tm := conf.InternalMp.MPTransport
	if tm == nil {
		lgSigner.Warn("pushKeystateInventoryToAllAgents: no TransportManager", "zone", zone)
		return
	}
	for _, agent := range mp.Agents {
		if agent.Identity == "" {
			continue
		}
		if err := sendKeystateInventoryToAgent(context.Background(), conf, tm, agent.Identity, zone, resend); err != nil {
			lgSigner.Error("pushKeystateInventoryToAllAgents: failed", "zone", zone, "agent", agent.Identity, "err", err)
		}
	}
}

// inventoryRequest is the KEYSTATE inventory a signer sends its agent, with
// the keys its key lifecycle sends again marked (resend, #256), and its
// marks (plan S11).
func inventoryRequest(sender, zone string, inventory []KeyInventoryEntry, owned bool, resend []uint16, marks inventoryMarks) *PeerKeystateRequest {
	return &PeerKeystateRequest{
		SenderID:     sender,
		Zone:         zone,
		Signal:       "inventory",
		KeyInventory: inventory,
		Owned:        owned,
		Resend:       resend,
		Acting:       marks.acting,
		NotSigning:   marks.notSigning,
		Rollover:     marks.rollover,
		WaitsOn:      marks.waitsOn,
		Timestamp:    time.Now(),
	}
}

// inventoryMarks are what a signer's inventory says beside its keys (plan
// S11): the hand-over it holds for the zone (nil: none), that it does not
// sign the zone by what it acts by, whether a key rollover is under way at
// this provider (rolloverUnderWay, on its own state), and for each key
// waiting in mpdist or mpremove, the other signers whose "applied" is
// missing.
type inventoryMarks struct {
	acting     *ActingHandover
	notSigning bool
	rollover   bool
	waitsOn    map[uint16][]string
}

// inventoryMarksOf are the zone's marks, given its key inventory. A zone
// this provider does not sign has no rollover under way: its key machine
// does not run there. One the machine runs is judged with what the machine
// knows beside the rows; one it does not run yet, by its rows alone.
func (conf *Config) inventoryMarksOf(zone string, items []KeyInventoryItem) inventoryMarks {
	var m inventoryMarks
	if held, ok := actingHeld.Load().get(zone); ok {
		m.acting = held.handover
	}
	if mpzd, ok := Zones.Get(zone); ok && mpzd.MP != nil && mpzd.MP.MPdata != nil && !mpzd.MP.MPdata.WeAreSigner {
		m.notSigning = true
		return m
	}
	var f rolloverFlags
	if e := conf.InternalMp.KeyLifecycle; e != nil {
		if l := e.driver(zone); l != nil {
			var err error
			if f, err = l.RolloverFlags(); err != nil {
				lgSigner.Error("key lifecycle: whether a rollover is under way could not be read; the inventory says one is", "zone", zone, "err", err)
				f.PropagationPending = true
			}
			if m.waitsOn, err = l.WaitsOn(); err != nil {
				lgSigner.Error("key lifecycle: what the keys in flight wait on could not be read", "zone", zone, "err", err)
			}
		}
	}
	m.rollover = rolloverUnderWay(items, f)
	return m
}

// sendKeystateInventoryToAgent queries KeyDB for all keys in the zone and sends
// a complete KEYSTATE inventory message back to the requesting agent.
func sendKeystateInventoryToAgent(ctx context.Context, conf *Config, tm *MPTransportBridge, agentID string, zone string, resend []uint16) error {
	hdb := NewHsyncDB(conf.Config.Internal.KeyDB)
	if hdb == nil {
		return fmt.Errorf("KeyDB not available")
	}

	// The real inventory, a zone this provider does not sign included,
	// marked as not signing: its agent withdraws nothing from it (plan
	// S11). Such a zone's keys are not the DS set's source, so it is not
	// said to be owned: its key machine does not run there.
	items, err := GetKeyInventory(hdb, zone)
	if err != nil {
		return fmt.Errorf("GetKeyInventory failed: %w", err)
	}
	marks := conf.inventoryMarksOf(zone, items)

	lgSigner.Debug("KeyDB inventory queried", "zone", zone, "keys", len(items), "notSigning", marks.notSigning)

	inventory := inventoryEntriesOf(items)
	owned := false
	if o := conf.InternalMp.KeyLifecycleOwner; o != nil && !marks.notSigning {
		if zd, ok := tdns.Zones.Get(zone); ok && zd != nil {
			owned = o.Owns(zd)
		}
	}

	// Look up agent peer in PeerRegistry
	if tm == nil || tm.DNSTransport == nil {
		return fmt.Errorf("TransportManager or DNSTransport not available")
	}
	if tm.PeerRegistry == nil {
		return fmt.Errorf("PeerRegistry not available")
	}

	peer, exists := tm.PeerRegistry.Get(agentID)
	if !exists || peer == nil {
		return fmt.Errorf("agent %q not found in PeerRegistry", agentID)
	}

	// Build and send KEYSTATE inventory
	req := inventoryRequest(conf.MpConfig().Identity, zone, inventory, owned, resend, marks)

	sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := tm.sendKeystate(sendCtx, peer, req)
	if err != nil {
		return fmt.Errorf("keystate send failed: %w", err)
	}

	if !resp.Accepted {
		return fmt.Errorf("agent %s rejected inventory: %s", agentID, resp.Message)
	}

	lgSigner.Info("KEYSTATE inventory sent", "zone", zone, "agent", agentID, "keys", len(inventory))
	return nil
}

// inventoryEntriesOf is the wire form of the key inventory: the row's
// state and its columns per key (S5, T5.1).
func inventoryEntriesOf(items []KeyInventoryItem) []KeyInventoryEntry {
	out := make([]KeyInventoryEntry, len(items))
	for i, item := range items {
		out[i] = KeyInventoryEntry{KeyTag: item.KeyTag, Algorithm: item.Algorithm, Flags: item.Flags, State: item.State, KeyRR: item.KeyRR,
			Pub: item.Pub, Sign: item.Sign, DS: item.DS}
	}
	return out
}

// inventoryItemsOf reads the wire form back. An entry without ds comes
// from a sender that predates the columns: the columns are then what the
// state implies, and ds stays unknown (T5.2).
func inventoryItemsOf(entries []KeyInventoryEntry) []KeyInventoryItem {
	out := make([]KeyInventoryItem, len(entries))
	for i, e := range entries {
		it := KeyInventoryItem{KeyTag: e.KeyTag, Algorithm: e.Algorithm, Flags: e.Flags, State: e.State, KeyRR: e.KeyRR, Pub: e.Pub, Sign: e.Sign, DS: e.DS}
		if e.DS == nil {
			it.Pub, it.Sign = impliedColumns(e.State)
		}
		out[i] = it
	}
	return out
}

// impliedColumns are pub and sign as the state implied them before the
// columns travelled (tdns's table of S1b, plus tdns-mp's states): what an
// entry from an older sender means.
func impliedColumns(state string) (pub, sign bool) {
	switch state {
	case tdns.DnskeyStateActive:
		return true, true
	case tdns.DnskeyStatePublished, tdns.DnskeyStateDsPublished, tdns.DnskeyStateStandby, tdns.DnskeyStateRetired,
		DnskeyStateMpdist, DnskeyStateForeign:
		return true, false
	}
	return false, false
}
