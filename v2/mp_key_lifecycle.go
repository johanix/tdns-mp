/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The multi-provider key lifecycle: the state machine tdns-mp runs for the
 * zones it owns (key lifecycle ownership design §5; step S3). The machine is
 * a table -- docs/2026-09-15-mp-key-lifecycle-transition-table.md -- and
 * this file is that table as data: the states with their columns, the
 * events, the transitions with their guards. The driver that applies it to a
 * keystore, and the harness that tests it, are elsewhere; nothing here
 * touches a database.
 */
package tdnsmp

import (
	"database/sql"
	"time"

	tdns "github.com/johanix/tdns/v2"
)

// Clock is the machine's clock, injectable for the tests (test plan T3.0).
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// RealClock is the clock the daemons run with.
var RealClock Clock = realClock{}

// KeyEvent is what happens to a key: an observation, a timer, a confirmation
// or a command (transition table §2).
type KeyEvent string

const (
	EvMint            KeyEvent = "mint"             // E1
	EvDistributed     KeyEvent = "distributed"      // E2
	EvApplied         KeyEvent = "applied"          // E3: a signing provider's final confirmation
	EvPending         KeyEvent = "pending"          // E3 with status pending: no confirmation
	EvRejected        KeyEvent = "rejected"         // E4
	EvPropagated      KeyEvent = "propagated"       // E5: the DNSKEY RRset propagated (timer)
	EvPromote         KeyEvent = "promote"          // E6: the rollover fires for this key
	EvSuccessorActive KeyEvent = "successor-active" // E6 seen from the key it replaces
	EvDSGone          KeyEvent = "ds-gone"          // E7
	EvMargin          KeyEvent = "margin"           // E8
	EvRemovalApplied  KeyEvent = "removal-applied"  // E9
	EvSignersChanged  KeyEvent = "signers-changed"  // E10
	EvRestart         KeyEvent = "restart"          // E11
	EvResend          KeyEvent = "resend"           // E12: a distribution unconfirmed for too long
	CmdRetry          KeyEvent = "retry"            // C1
	CmdWithdraw       KeyEvent = "withdraw"         // C2
)

// The states, as the keystore names them. tdns's own names are reused where
// the meaning is the same; the three multi-provider states are tdns-mp's.
const (
	KeyStateCreated   = tdns.DnskeyStateCreated
	KeyStateMpdist    = DnskeyStateMpdist
	KeyStatePublished = tdns.DnskeyStatePublished
	KeyStateStandby   = tdns.DnskeyStateStandby
	KeyStateActive    = tdns.DnskeyStateActive
	KeyStateRetired   = tdns.DnskeyStateRetired
	KeyStateMpremove  = DnskeyStateMpremove
	KeyStateRemoved   = tdns.DnskeyStateRemoved
	KeyStateForeign   = DnskeyStateForeign
)

// KeyLifecycleStates are the states of the zone's own keys, in lifecycle
// order. Foreign rows are not the machine's own state (transition table §3).
var KeyLifecycleStates = []string{
	KeyStateCreated, KeyStateMpdist, KeyStatePublished, KeyStateStandby,
	KeyStateActive, KeyStateRetired, KeyStateMpremove, KeyStateRemoved,
}

func dsCol(v bool) sql.NullBool { return sql.NullBool{Bool: v, Valid: true} }

// KeyStateColumns is the transition table's §1: the columns a key carries in
// a state. ds is for a KSK; a ZSK's is 0 in every state. retired is the state
// in which a KSK's ds goes from 1 to 0: on entry it is still 1, and
// withdrawn is what the machine writes once the DS withdrawal has started.
func KeyStateColumns(state string, sep bool, withdrawn bool) (tdns.KeyRowFlags, bool) {
	var f tdns.KeyRowFlags
	switch state {
	case KeyStateCreated, KeyStateMpremove, KeyStateRemoved:
		f = tdns.KeyRowFlags{DS: dsCol(false)}
	case KeyStateMpdist, KeyStatePublished:
		f = tdns.KeyRowFlags{Pub: true, DS: dsCol(false)}
	case KeyStateStandby:
		f = tdns.KeyRowFlags{Pub: true, DS: dsCol(sep)}
	case KeyStateActive:
		f = tdns.KeyRowFlags{Pub: true, Sign: true, DS: dsCol(sep)}
	case KeyStateRetired:
		f = tdns.KeyRowFlags{Pub: true, DS: dsCol(sep && !withdrawn)}
	default:
		return tdns.KeyRowFlags{}, false
	}
	return f, true
}

// KeyView is what a guard may ask about the key the event concerns.
type KeyView struct {
	State       string
	SEP         bool
	Algorithm   uint8
	PublishedAt time.Time // when it entered published
	RetiredAt   time.Time // when it entered retired
	Withdrawn   bool      // retired KSK: its DS withdrawal has been written (ds=0)
	DSGone      bool      // retired KSK: the parent no longer serves its DS
}

// ZoneView is what a guard may ask about the zone the key belongs to, as
// this provider sees it.
type ZoneView struct {
	// OtherSigners are the other signing providers (HSYNCPARAM signers minus
	// this one); none means nobody to wait for (§5.5).
	OtherSigners []string
	// Applied, Pending and Rejected are the confirmations received for the
	// key's current distribution, by provider.
	Applied  map[string]bool
	Pending  map[string]bool
	Rejected map[string]bool
	// PropagationDelay plus ServedDnskeyTTL is the wait behind E5; Margin
	// the wait behind E8.
	PropagationDelay time.Duration
	ServedDnskeyTTL  time.Duration
	Margin           time.Duration
	// ActiveOfRoleAndAlg reports another active key of the key's role and
	// algorithm on this provider. RolloverRequested says the promotion is a
	// rollover, requested or due: the active key retires in the same step.
	// AlgRollInFlight lifts P5's one-per-role rule for the roll's duration.
	ActiveOfRoleAndAlg bool
	RolloverRequested  bool // the promotion under way is a rollover (T9)
	RolloverPending    bool // a rollover of the role has been requested and not fired (C3, T1)
	AlgRollInFlight    bool
	// StandbyCount is the policy's standby count for the key's role, and
	// InPipeline how many keys of the role are in created..standby.
	StandbyCount   int
	InPipeline     int
	LifetimeDue    bool
	NoActiveOfRole bool
	Now            time.Time
}

// allOtherSignersApplied is G1: every other signing provider has sent a
// final confirmation that it applied the key, and none rejected it. A
// rejection sticks to the distribution: an "applied" from the same
// provider for the same distribution does not lift it, only a retry (C1)
// starts a distribution without it.
func allOtherSignersApplied(z ZoneView) bool {
	if len(z.Rejected) > 0 {
		return false
	}
	for _, p := range z.OtherSigners {
		if !z.Applied[p] {
			return false
		}
	}
	return true
}

// distributionIncomplete: the key's distribution has not been applied by
// every signer expected, or someone rejected it. What keeps a key from
// signing (T9): a rejection is never promoted over (P8).
func distributionIncomplete(z ZoneView) bool {
	if len(z.Rejected) > 0 {
		return true
	}
	for _, p := range z.OtherSigners {
		if !z.Applied[p] {
			return true
		}
	}
	return false
}

// confirmationsOutstanding: a signer expected to confirm has not, and
// nobody rejected (a rejection waits for the operator, not a resend).
func confirmationsOutstanding(z ZoneView) bool {
	if len(z.Rejected) > 0 {
		return false
	}
	for _, p := range z.OtherSigners {
		if !z.Applied[p] {
			return true
		}
	}
	return false
}

// Transition is one row of the table: from state, on event, if guard, to
// state. Guards see the key and the zone; a nil guard always holds.
type Transition struct {
	ID    string
	From  string
	Event KeyEvent
	Guard func(k KeyView, z ZoneView) bool
	To    string
	Note  string
}

// KeyLifecycleTable is the machine (transition table §3). The first row
// whose from, event and guard match wins; no row means "no change".
var KeyLifecycleTable = []Transition{
	{"T1", "", EvMint, func(k KeyView, z ZoneView) bool {
		return z.InPipeline < z.StandbyCount || z.LifetimeDue || z.NoActiveOfRole || (z.RolloverPending && z.InPipeline == 0)
	}, KeyStateCreated, "minted through tdns's keystore, state and columns named"},
	{"T2", KeyStateCreated, EvDistributed, nil, KeyStateMpdist, "the distribution recorded with the signing providers expected to confirm"},
	{"T3", KeyStateMpdist, EvApplied, func(k KeyView, z ZoneView) bool { return allOtherSignersApplied(z) }, KeyStatePublished, "published_at stamped"},
	{"T3'", KeyStateMpdist, EvDistributed, func(k KeyView, z ZoneView) bool { return len(z.OtherSigners) == 0 }, KeyStatePublished, "no other signing provider: at once"},
	{"T4", KeyStateMpdist, EvPending, nil, KeyStateMpdist, "nothing: pending is not applied (P9)"},
	{"T5", KeyStateMpdist, EvRejected, nil, KeyStateMpdist, "the rejection recorded and surfaced; no automatic retreat (P8)"},
	{"T6", "*", CmdRetry, nil, "*", "a fresh distribution: the expected set recomputed from the current signers, the rejection forgotten"},
	{"T6'", "*", EvResend, func(k KeyView, z ZoneView) bool { return confirmationsOutstanding(z) }, "*", "a distribution in flight sent again, whatever the key's state; the confirmations received stay"},
	{"T7", KeyStateMpdist, CmdWithdraw, nil, KeyStateMpremove, "the removal distributed"},
	{"T7'", KeyStatePublished, CmdWithdraw, nil, KeyStateMpremove, "a served key given up on: the removal distributed"},
	{"T7''", KeyStateStandby, CmdWithdraw, nil, KeyStateMpremove, "as T7'"},
	{"T8", KeyStatePublished, EvPropagated, func(k KeyView, z ZoneView) bool {
		return !k.PublishedAt.IsZero() && !z.Now.Before(k.PublishedAt.Add(z.PropagationDelay+z.ServedDnskeyTTL))
	}, KeyStateStandby, "a KSK's ds=1 puts its DS into the zone's DS set"},
	{"T9", KeyStateStandby, EvPromote, func(k KeyView, z ZoneView) bool {
		return (!z.ActiveOfRoleAndAlg || z.RolloverRequested || z.AlgRollInFlight) && !distributionIncomplete(z)
	}, KeyStateActive, "the previous active key of the role retires in the same step; resign asked of tdns"},
	{"T10", KeyStateActive, EvSuccessorActive, nil, KeyStateRetired, "retired_at stamped; a KSK's ds withdrawal starts: ds=0"},
	{"T11", KeyStateRetired, EvDSGone, nil, KeyStateRetired, "the parent no longer serves the DS; noted for T12"},
	{"T12", KeyStateRetired, EvMargin, func(k KeyView, z ZoneView) bool {
		if k.SEP && !k.DSGone {
			return false
		}
		return !k.RetiredAt.IsZero() && !z.Now.Before(k.RetiredAt.Add(z.Margin))
	}, KeyStateMpremove, "tdns asked to strip the key's RRSIGs; the removal distributed"},
	{"T13", KeyStateMpremove, EvRemovalApplied, func(k KeyView, z ZoneView) bool { return allOtherSignersApplied(z) }, KeyStateRemoved, "the propagation record dropped"},
	{"T13'", KeyStateMpremove, EvDistributed, func(k KeyView, z ZoneView) bool { return len(z.OtherSigners) == 0 }, KeyStateRemoved, "no other signing provider: at once"},
	{"T14a", KeyStateMpdist, EvSignersChanged, nil, KeyStateMpdist, "the expected set recomputed; T3 re-evaluated; a signer that joined gets this provider's served keys again"},
	{"T14b", KeyStateMpremove, EvSignersChanged, nil, KeyStateMpremove, "the expected set recomputed; T13 re-evaluated"},
	{"T15", "*", EvRestart, nil, "*", "in-flight distributions re-sent; timers re-armed from the stamps (P4)"},
}

// Next applies the table to one key: the state after the event, and whether
// a row matched. "*" rows keep the state.
func Next(k KeyView, ev KeyEvent, z ZoneView) (string, *Transition) {
	for i := range KeyLifecycleTable {
		t := &KeyLifecycleTable[i]
		if t.Event != ev || (t.From != "*" && t.From != k.State) {
			continue
		}
		if t.Guard != nil && !t.Guard(k, z) {
			continue
		}
		if t.To == "*" {
			return k.State, t
		}
		return t.To, t
	}
	return k.State, nil
}
