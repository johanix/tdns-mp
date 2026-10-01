/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"testing"
	"time"
)

func localRow(gst *GossipStateTable, group string) *MemberState {
	gst.mu.RLock()
	defer gst.mu.RUnlock()
	return gst.States[group][gst.LocalID]
}

// After a start, an agent's first row of a group goes out only with good news,
// every other member OPERATIONAL from here, until one beat interval has
// passed. A row it has written once is refreshed from then on, good news or
// bad, and a table with no hold writes every row at once, as before.
func TestTheFirstLocalRowWaitsForGoodNews(t *testing.T) {
	const group = "0123456789abcdef"
	op := AgentStateToString[AgentStateOperational]
	known := AgentStateToString[AgentStateKnown]
	zones := []string{"zone.example."}
	now := time.Now()

	gst := NewGossipStateTable("a.example.")
	gst.HoldFirstLocalRows(now.Add(30 * time.Second))

	if gst.refreshLocalRow(group, map[string]string{"b.example.": op, "c.example.": known}, zones, 30, now) {
		t.Fatal("a first row with a member not OPERATIONAL was written in the hold")
	}
	if localRow(gst, group) != nil {
		t.Fatal("the held row is in the table")
	}

	if !gst.refreshLocalRow(group, map[string]string{"b.example.": op, "c.example.": op}, zones, 30, now.Add(time.Second)) {
		t.Fatal("a first row with every member OPERATIONAL was held")
	}

	// Written once: refreshed from now on, whatever it says.
	if !gst.refreshLocalRow(group, map[string]string{"b.example.": op, "c.example.": known}, zones, 30, now.Add(2*time.Second)) {
		t.Fatal("a row already written was held")
	}
	if row := localRow(gst, group); row == nil || row.PeerStates["c.example."] != known {
		t.Fatalf("the refreshed row is %+v, want c.example. %s", row, known)
	}

	// Another group, after the hold: written at once.
	if !gst.refreshLocalRow("fedcba9876543210", map[string]string{"b.example.": known}, zones, 30, now.Add(31*time.Second)) {
		t.Fatal("a first row after the hold was held")
	}

	// No hold at all: written at once, as before.
	plain := NewGossipStateTable("a.example.")
	if !plain.refreshLocalRow(group, map[string]string{"b.example.": known}, zones, 30, now) {
		t.Fatal("a table with no hold held a row")
	}
}

// A restarted agent hears its own row from before the restart in its peers'
// gossip. That row is not one this process wrote, and the hold still applies.
func TestAnOwnRowHeardInGossipDoesNotEndTheHold(t *testing.T) {
	const group = "0123456789abcdef"
	op := AgentStateToString[AgentStateOperational]
	known := AgentStateToString[AgentStateKnown]
	now := time.Now()

	gst := NewGossipStateTable("a.example.")
	gst.HoldFirstLocalRows(now.Add(30 * time.Second))
	gst.MergeGossip(&GossipMessage{
		GroupHash: group,
		Members: map[string]*MemberState{
			"a.example.": {Identity: "a.example.", PeerStates: map[string]string{"b.example.": op},
				Timestamp: now.Add(-time.Minute)},
		},
	})

	if gst.refreshLocalRow(group, map[string]string{"b.example.": known}, nil, 30, now) {
		t.Fatal("the own row heard in gossip ended the hold")
	}
}
