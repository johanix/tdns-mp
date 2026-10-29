/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The serials an agent keeps per zone, on disk (design rule 3, plan S2): the
 * active serial and its instructions, the serial it was thawed from until the
 * transition is done, every newer serial held, the last thaw, an owner error,
 * the step and its sets, and the removals under way. Kept on the agent and on
 * the auditor. From the thaw (S7) the active serial moves only by Activate:
 * a newer copy is held, and agreed on, and a refused one is never made
 * active. A record kept before that followed the copy, "not enforced", and
 * counts as none: the copy noted next becomes the active serial, enforced
 * (S9 replaces that with the restart rule).
 */
package tdnsmp

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/johanix/tdns-mp/v2/hsync"
	tdns "github.com/johanix/tdns/v2"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// SerialDigest names a set of the owner's instructions: its serial, checked
// by its digest (design rule 2). Defined in package hsync with the stamp
// that carries it (plan S5a).
type SerialDigest = hsync.SerialDigest

// Thaw is a thaw's pair of serials, from N to V (design 3.2).
type Thaw = hsync.Thaw

// heldSerial is a serial the agent holds, with its instructions, and the
// judge's refusal of it against the active serial (S4), if any; until S7,
// the active serial's own refusal against the serial it followed.
type heldSerial struct {
	SerialDigest
	Reading *Instructions `json:"reading"`
	Refused []Refusal     `json:"refused,omitempty"`
	Since   time.Time     `json:"since"`
}

// Removal is a leaving provider's removal under way, as the leader's first
// step names it (S12, S17b): its label and identity, the step this agent
// holds, and its nameserver names.
type Removal struct {
	Label    string    `json:"label"`
	Identity string    `json:"identity"`
	Step     int       `json:"step"`
	NSNames  []string  `json:"ns_names,omitempty"`
	Since    time.Time `json:"since"`
}

// zoneSerials is what the agent keeps of one zone's instructions. Its phase
// follows from it (phase).
type zoneSerials struct {
	Copy      SerialDigest `json:"copy"`                 // the copy as last noted
	CopyError string       `json:"copy_error,omitempty"` // or why it has no reading
	Active    *heldSerial  `json:"active,omitempty"`
	From      *heldSerial  `json:"from,omitempty"` // thawed from, until "done"
	Held      []heldSerial `json:"held,omitempty"` // above Active, lowest first
	LastThaw  *Thaw        `json:"last_thaw,omitempty"`
	// LastFrom is the last thaw's from-serial, kept after "done" until the
	// next thaw, so that a member behind the thaw can fetch it here (the
	// instructions RFI, plan S7).
	LastFrom *heldSerial `json:"last_from,omitempty"`
	// OwnerError holds the zone (design 3.6) until a copy above ErrorAt is
	// noted; ErrorAt nil: nothing was held when it was noted. Conflict is
	// the digests seen at ErrorAt for "one serial, two digests".
	OwnerError string   `json:"owner_error,omitempty"`
	ErrorAt    *uint32  `json:"error_at,omitempty"`
	Conflict   []string `json:"conflict,omitempty"`
	// Step and Sets are the reconciliation's step and the sets the parts
	// hold at it, each provider by label and identity, as Roles in JSON
	// (S12): nil at rest, and while this agent holds no step's sets
	// (Pending). StepOf, StepWhat and Taken are the leader's plan as the
	// step names it: how many steps, what this one does, and the keys of
	// the steps taken. StepAt is when this agent took or first heard the
	// step.
	Step     int             `json:"step,omitempty"`
	Sets     json.RawMessage `json:"sets,omitempty"`
	StepOf   int             `json:"step_of,omitempty"`
	StepWhat string          `json:"step_what,omitempty"`
	Taken    []string        `json:"taken,omitempty"`
	StepAt   time.Time       `json:"step_at,omitzero"`
	// Pending: a transition to the active serial may be under way, and this
	// agent holds no step's sets. It moved straight to the active serial
	// (S7) or knew it by another's word (S9): it hands its parts nothing
	// new until the leader's stamp gives it the step (design 3.3).
	Pending bool `json:"pending,omitempty"`
	// Excused are the leaving members the leader excused during the
	// reconciliation, by identity (design 3.2): planned as excused from
	// then on.
	Excused []string `json:"excused,omitempty"`
	// DoneAt is when the last transition was done here (S12).
	DoneAt time.Time `json:"done_at,omitzero"`
	// Enforced: the active serial moves only by Activate (S7). A record
	// kept before that followed the copy.
	Enforced bool      `json:"enforced"`
	Removals []Removal `json:"-"` // in MPZoneRemovals
	Since    time.Time `json:"since"`
}

// The phases of a zone (design 3). Refused is steady at the active serial
// with the newest serial refused (design 3.6): not frozen.
const (
	PhaseSteady      = "steady"
	PhaseRefused     = "refused"
	PhaseAgreeing    = "agreeing"
	PhaseReconciling = "reconciling"
	PhaseOwnerError  = "owner error"
)

func (z *zoneSerials) phase() string {
	switch {
	case z.OwnerError != "":
		return PhaseOwnerError
	case z.reconciling():
		return PhaseReconciling
	case z.agreeing() != nil:
		return PhaseAgreeing
	case z.highest() != nil && len(z.highest().Refused) > 0:
		return PhaseRefused
	}
	return PhaseSteady
}

// reconciling: a transition to the active serial is under way here (design
// 3.3): it holds the serial it was thawed from, a step's sets, or a removal,
// or holds no step's sets yet (Pending).
func (z *zoneSerials) reconciling() bool {
	return z.From != nil || len(z.Removals) > 0 || z.Sets != nil || z.Pending
}

// agreeing is the serial agreed on: the highest serial held above the active
// one that the judge accepts against it (design 3.1, decision 94); nil with
// none.
func (z *zoneSerials) agreeing() *heldSerial {
	for i := len(z.Held) - 1; i >= 0; i-- {
		if len(z.Held[i].Refused) == 0 {
			return &z.Held[i]
		}
	}
	return nil
}

// judged judges every serial held above the active one against it, as the
// judge is asked again whenever the active serial changes (plan S4). Called
// inside update.
func (s *InstructionStore) judged(zone string, z *zoneSerials) {
	for i := range z.Held {
		s.judge(zone, z.Active, &z.Held[i])
	}
}

// judge judges h against the serial against, and logs a refusal once per
// zone and serial. Called inside update.
func (s *InstructionStore) judge(zone string, against, h *heldSerial) {
	h.Refused = judgeTransition(against.Reading, h.Reading)
	key := zoneSerial{zone, h.Serial}
	if len(h.Refused) == 0 || s.refusedLogged[key] {
		return
	}
	s.refusedLogged[key] = true
	reasons := make([]string, len(h.Refused))
	for i, r := range h.Refused {
		reasons[i] = r.Reason
	}
	lg.Warn("a change of the zone's instructions is refused", "zone", zone, "from", against.Serial, "to", h.Serial, "reason", strings.Join(reasons, "; "))
}

// held returns the serial held at serial, the active one or a newer one.
func (z *zoneSerials) held(serial uint32) *heldSerial {
	if z.Active != nil && z.Active.Serial == serial {
		return z.Active
	}
	for i := range z.Held {
		if z.Held[i].Serial == serial {
			return &z.Held[i]
		}
	}
	return nil
}

// highest is the highest serial held: the newest, or the active one.
func (z *zoneSerials) highest() *heldSerial {
	if n := len(z.Held); n > 0 {
		return &z.Held[n-1]
	}
	return z.Active
}

// dropAtOrBelow drops the newer serials held at or below serial.
func (z *zoneSerials) dropAtOrBelow(serial uint32) {
	z.Held = slices.DeleteFunc(z.Held, func(h heldSerial) bool { return CompareSerial(h.Serial, serial) <= 0 })
}

// InstructionStore keeps every zone's serials, in memory and in HsyncDB.
// Every change is written before it returns, so before it can be told.
type InstructionStore struct {
	mu            sync.Mutex
	hdb           *HsyncDB // nil: in memory only
	zones         map[string]*zoneSerials
	warnedOld     map[string]time.Time // the last "not adopted" warning per zone
	refusedLogged map[zoneSerial]bool  // the refusals logged, once each
	// onFreeze is told when a zone is frozen, when it no longer is, and
	// when the serial it agrees on moves while it stays frozen
	// (instr_freeze.go), after the change is written and the lock let go.
	onFreeze func(zone string, frozen bool)
}

type zoneSerial struct {
	zone   string
	serial uint32
}

// LoadInstructionStore reads every zone's stored serials, before the zones'
// first load.
func LoadInstructionStore(hdb *HsyncDB) (*InstructionStore, error) {
	s := &InstructionStore{hdb: hdb, zones: map[string]*zoneSerials{}, warnedOld: map[string]time.Time{}, refusedLogged: map[zoneSerial]bool{}}
	if hdb == nil {
		return s, nil
	}
	hdb.Lock()
	defer hdb.Unlock()
	rows, err := hdb.DB.Query(`SELECT zonename, state FROM MPZoneInstructions`)
	if err != nil {
		return nil, fmt.Errorf("reading the zones' serials: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var zone, state string
		if err := rows.Scan(&zone, &state); err != nil {
			return nil, fmt.Errorf("reading the zones' serials: %w", err)
		}
		z := &zoneSerials{}
		if err := json.Unmarshal([]byte(state), z); err != nil {
			return nil, fmt.Errorf("the stored serials of %s: %w", zone, err)
		}
		s.zones[zone] = z
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading the zones' serials: %w", err)
	}
	rrows, err := hdb.DB.Query(`SELECT zonename, label, identity, step, ns_names, since FROM MPZoneRemovals ORDER BY zonename, label`)
	if err != nil {
		return nil, fmt.Errorf("reading the removals under way: %w", err)
	}
	defer rrows.Close()
	for rrows.Next() {
		var zone, nsNames, since string
		var r Removal
		if err := rrows.Scan(&zone, &r.Label, &r.Identity, &r.Step, &nsNames, &since); err != nil {
			return nil, fmt.Errorf("reading the removals under way: %w", err)
		}
		if nsNames != "" {
			if err := json.Unmarshal([]byte(nsNames), &r.NSNames); err != nil {
				return nil, fmt.Errorf("the nameserver names of %s's removal in %s: %w", r.Label, zone, err)
			}
		}
		r.Since, _ = time.Parse(time.RFC3339, since)
		if z := s.zones[zone]; z != nil {
			z.Removals = append(z.Removals, r)
		}
	}
	return s, rrows.Err()
}

// persist writes zone's serials, or deletes them when z is nil. Called with
// s.mu held.
func (s *InstructionStore) persist(zone string, z *zoneSerials) error {
	if s.hdb == nil {
		return nil
	}
	s.hdb.Lock()
	defer s.hdb.Unlock()
	tx, err := s.hdb.DB.Begin()
	if err != nil {
		return fmt.Errorf("keeping the serials of %s: %w", zone, err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM MPZoneRemovals WHERE zonename = ?`, zone); err != nil {
		return fmt.Errorf("keeping the removals of %s: %w", zone, err)
	}
	if z == nil {
		if _, err := tx.Exec(`DELETE FROM MPZoneInstructions WHERE zonename = ?`, zone); err != nil {
			return fmt.Errorf("forgetting the serials of %s: %w", zone, err)
		}
		return tx.Commit()
	}
	state, err := json.Marshal(z)
	if err != nil {
		return fmt.Errorf("keeping the serials of %s: %w", zone, err)
	}
	var active sql.NullInt64
	var digest string
	if z.Active != nil {
		active = sql.NullInt64{Int64: int64(z.Active.Serial), Valid: true}
		digest = z.Active.Digest
	}
	if _, err := tx.Exec(`INSERT INTO MPZoneInstructions (zonename, active, digest, phase, enforced, state, since) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(zonename) DO UPDATE SET active = excluded.active, digest = excluded.digest, phase = excluded.phase,
		enforced = excluded.enforced, state = excluded.state, since = excluded.since`,
		zone, active, digest, z.phase(), z.Enforced, string(state), z.Since.UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("keeping the serials of %s: %w", zone, err)
	}
	for _, r := range z.Removals {
		ns, err := json.Marshal(r.NSNames)
		if err != nil {
			return fmt.Errorf("keeping %s's removal in %s: %w", r.Label, zone, err)
		}
		if _, err := tx.Exec(`INSERT INTO MPZoneRemovals (zonename, label, identity, step, ns_names, since) VALUES (?, ?, ?, ?, ?, ?)`,
			zone, r.Label, r.Identity, r.Step, string(ns), r.Since.UTC().Format(time.RFC3339)); err != nil {
			return fmt.Errorf("keeping %s's removal in %s: %w", r.Label, zone, err)
		}
	}
	return tx.Commit()
}

// update applies f to zone's serials, creating them if needed, and writes
// the result; f returning an error changes nothing, and so does a result
// equal to what was kept (a refresh that brings the same copy). f returning
// errEndOfService drops the zone's serials, under the same lock. A change
// that freezes the zone, ends its freeze, or moves the serial a frozen
// zone agrees on, is told to onFreeze once the lock is let go.
func (s *InstructionStore) update(zone string, f func(z *zoneSerials) error) error {
	var froze *bool
	defer func() {
		if froze != nil && s.onFreeze != nil {
			s.onFreeze(zone, *froze)
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.zones[zone]
	z := &zoneSerials{}
	if old != nil {
		z = old.clone()
	}
	wasFrozen := old != nil && len(old.freezeReasons()) > 0
	var wasAgreed SerialDigest
	if old != nil && old.agreeing() != nil {
		wasAgreed = old.agreeing().SerialDigest
	}
	if err := f(z); err != nil {
		if errors.Is(err, errEndOfService) {
			if ferr := s.forgetLocked(zone); ferr != nil {
				return fmt.Errorf("dropping the zone's serials: %w", ferr)
			}
			if wasFrozen {
				froze = new(bool)
			}
		}
		return err
	}
	if old != nil {
		z.Since = old.Since
		if reflect.DeepEqual(z, old) {
			return nil
		}
	}
	z.Since = time.Now()
	if err := s.persist(zone, z); err != nil {
		return err
	}
	s.zones[zone] = z
	frozen := len(z.freezeReasons()) > 0
	moved := frozen && z.agreeing() != nil && z.agreeing().SerialDigest != wasAgreed
	if frozen != wasFrozen || moved {
		froze = &frozen
	}
	return nil
}

// clone copies what f may change in place; a reading is never changed.
func (z *zoneSerials) clone() *zoneSerials {
	c := *z
	if z.Active != nil {
		a := *z.Active
		c.Active = &a
	}
	if z.From != nil {
		f := *z.From
		c.From = &f
	}
	if z.LastFrom != nil {
		f := *z.LastFrom
		c.LastFrom = &f
	}
	c.Held = slices.Clone(z.Held)
	c.Conflict = slices.Clone(z.Conflict)
	c.Removals = slices.Clone(z.Removals)
	c.Taken = slices.Clone(z.Taken)
	c.Excused = slices.Clone(z.Excused)
	return &c
}

// ownerError notes an owner error that holds the zone until a copy above the
// highest serial held now (design 3.6). Called inside update.
func (z *zoneSerials) ownerError(zone, msg string) {
	if z.OwnerError != msg {
		lg.Warn("owner error in the zone's instructions", "zone", zone, "error", msg)
	}
	z.OwnerError = msg
	if z.ErrorAt == nil {
		if h := z.highest(); h != nil {
			at := h.Serial
			z.ErrorAt = &at
		}
	}
}

// Note classifies a copy of the zone's instructions, at its first load and
// at every refresh (plan S2): its reading, or the error that it has none
// (readErr), or neither for a copy with neither record.
func (s *InstructionStore) Note(zone string, in *Instructions, readErr error) {
	if s == nil {
		return
	}
	if in == nil && readErr == nil {
		s.mu.Lock()
		_, kept := s.zones[zone]
		s.mu.Unlock()
		if !kept {
			return
		}
	}
	err := s.update(zone, func(z *zoneSerials) error {
		switch {
		case readErr != nil:
			z.Copy, z.CopyError = SerialDigest{}, readErr.Error()
			z.ownerError(zone, readErr.Error())
			return nil
		case in == nil:
			if z.Active != nil && len(z.Active.Reading.Records) > 1 {
				z.Copy, z.CopyError = SerialDigest{}, "no HSYNC3 and no HSYNCPARAM"
				z.ownerError(zone, fmt.Sprintf("HSYNC3 and HSYNCPARAM dropped while serial %d lists %d providers", z.Active.Serial, len(z.Active.Reading.Records)))
				return nil
			}
			return errEndOfService
		}
		cp := SerialDigest{Serial: in.Serial, Digest: in.Digest()}
		z.Copy, z.CopyError = cp, ""
		if !in.HasParam && (z.Active != nil && z.Active.Reading.HasParam ||
			slices.ContainsFunc(z.Held, func(h heldSerial) bool { return h.Reading.HasParam })) {
			z.ownerError(zone, fmt.Sprintf("HSYNCPARAM dropped at serial %d while HSYNC3 stays", in.Serial))
			return nil
		}
		if h := z.held(in.Serial); h != nil {
			if h.Digest != cp.Digest {
				// an edit without a raised serial; at serial 0, a change of a
				// zone that has no serial key
				if z.ErrorAt == nil || *z.ErrorAt != in.Serial {
					z.Conflict = []string{h.Digest}
				}
				if !slices.Contains(z.Conflict, cp.Digest) {
					z.Conflict = append(z.Conflict, cp.Digest)
				}
				at := in.Serial
				z.ErrorAt = &at
				digests := fmt.Sprintf("%d digests", len(z.Conflict))
				if len(z.Conflict) == 2 {
					digests = "two digests"
				}
				z.ownerError(zone, fmt.Sprintf("serial %d with %s (%s)", in.Serial, digests, strings.Join(z.Conflict, ", ")))
			}
			// a record kept before the thaw is enforced at its serial, an
			// edit at that serial or not: the readers act by it, not by a
			// copy the owner changed without raising the serial (plan S7)
			z.Enforced = true
			return nil
		}
		if top := z.highest(); top != nil && CompareSerial(in.Serial, top.Serial) <= 0 {
			if time.Since(s.warnedOld[zone]) >= time.Hour {
				lg.Warn("a copy of the zone's instructions below the highest held is not adopted", "zone", zone, "copy", in.Serial, "highest", top.Serial)
				s.warnedOld[zone] = time.Now()
			}
			return nil
		}
		// A newer serial. An owner error ends at a serial above the one it
		// was noted at.
		if z.OwnerError != "" && (z.ErrorAt == nil || CompareSerial(in.Serial, *z.ErrorAt) > 0) {
			z.OwnerError, z.ErrorAt, z.Conflict = "", nil, nil
		}
		h := heldSerial{SerialDigest: cp, Reading: in, Since: time.Now()}
		if z.Active == nil || !z.Enforced {
			// The zone's first record, or one kept before the thaw enforced
			// the active serial, which followed the copy and counts as none
			// (plan section 4): the copy becomes the active serial, enforced.
			// From here it moves only by Activate (S7). S9 replaces this with
			// the restart rule.
			z.Active = &h
			z.dropAtOrBelow(in.Serial)
			z.Enforced = true
			return nil
		}
		s.judge(zone, z.Active, &h)
		z.Held = append(z.Held, h)
		return nil
	})
	switch {
	case errors.Is(err, errEndOfService):
		// The end of multi-provider service (design 7): update dropped the
		// zone's serials.
		lg.Info("the zone's HSYNC3 and HSYNCPARAM records are gone with at most one provider listed; its serials end", "zone", zone)
	case err != nil:
		lg.Error("the zone's serials could not be kept", "zone", zone, "err", err)
	}
}

var errEndOfService = errors.New("the zone's instructions are gone")

// Activate makes the thaw's target the zone's active serial (S7). It
// succeeds only when the target is held, above the active serial and not
// refused, and the thaw's from-serial is held: the active one, or for a
// member behind it, a newer one (design 3.2). Such a member judges the
// thaw's own pair, never its active serial against the target (S4). The
// from-serial is kept until "done"; serials at or below the target are
// dropped, and those above it are judged against it. The parts keep the
// sets they hold: step 0 of the new transition is the sets of the step this
// agent held, or with none the from-serial's lists (design 3.3). A member
// that moves straight holds no step's sets: its parts hold an older
// serial's, and it waits for the leader's step (Pending). What the
// transition before it left (an agent that missed its end) is dropped.
func (s *InstructionStore) Activate(zone string, thaw Thaw) error {
	return s.update(zone, func(z *zoneSerials) error {
		if z.Active == nil {
			return fmt.Errorf("zone %s: no active serial", zone)
		}
		to := z.held(thaw.To.Serial)
		switch {
		case to == nil || to.SerialDigest != thaw.To:
			return fmt.Errorf("zone %s: serial %s is not held", zone, thaw.To)
		case CompareSerial(to.Serial, z.Active.Serial) <= 0:
			return fmt.Errorf("zone %s: serial %d is not above the active serial %d", zone, to.Serial, z.Active.Serial)
		}
		from := z.held(thaw.From.Serial)
		if from == nil || from.SerialDigest != thaw.From || CompareSerial(from.Serial, to.Serial) >= 0 {
			return fmt.Errorf("zone %s: the thaw's from-serial %s is not held below its target", zone, thaw.From)
		}
		refused := to.Refused
		if from != z.Active {
			refused = judgeTransition(from.Reading, to.Reading)
		}
		if len(refused) > 0 {
			return fmt.Errorf("zone %s: serial %d is refused: %s", zone, to.Serial, refusalText(refused))
		}
		straight := from != z.Active
		f, t := *from, *to
		t.Since, t.Refused = time.Now(), nil
		z.From, z.Active = &f, &t
		lf := f
		z.LastFrom = &lf
		z.dropAtOrBelow(t.Serial)
		s.judged(zone, z)
		sets := z.Sets
		if sets == nil {
			var err error
			if sets, err = json.Marshal(rolesFor(f.Reading, f.Reading, 0)); err != nil {
				return fmt.Errorf("zone %s: the sets held: %w", zone, err)
			}
		}
		z.Step, z.Removals, z.Taken, z.StepOf, z.StepWhat, z.Excused = 0, nil, nil, 0, "", nil
		z.Sets, z.StepAt, z.Pending, z.DoneAt = sets, time.Now(), false, time.Time{}
		if straight {
			z.Sets, z.Pending = nil, true
		}
		z.LastThaw = &thaw
		z.Enforced = true
		return nil
	})
}

var errHeldAlready = errors.New("the serial is held already")

// Hold keeps a serial fetched from a member (the instructions RFI, plan S7):
// a from-serial that a member behind the thaw lacks, or a serial agreed on
// or made active that it does not hold. It is kept in order among the newer
// serials held and judged against the active serial. One at or below the
// active serial is not kept, nor one held already (errHeldAlready); one held
// with another digest is refused: the owner errors between agents are the
// stamps' (S5a).
func (s *InstructionStore) Hold(zone string, in *Instructions) error {
	if s == nil || in == nil {
		return fmt.Errorf("zone %s: no serials kept", zone)
	}
	name := zone
	s.mu.Lock()
	if n, _ := s.zoneLocked(zone); n != "" {
		name = n
	}
	s.mu.Unlock()
	return s.update(name, func(z *zoneSerials) error {
		if z.Active == nil || !z.Enforced {
			return fmt.Errorf("zone %s: no enforced active serial", zone)
		}
		sd := SerialDigest{Serial: in.Serial, Digest: in.Digest()}
		if h := z.held(sd.Serial); h != nil {
			if h.Digest != sd.Digest {
				return fmt.Errorf("zone %s: serial %d is held with digest %s, not %s", zone, sd.Serial, h.Digest, sd.Digest)
			}
			return errHeldAlready
		}
		if CompareSerial(sd.Serial, z.Active.Serial) <= 0 {
			return fmt.Errorf("zone %s: serial %d is not above the active serial %d", zone, sd.Serial, z.Active.Serial)
		}
		h := heldSerial{SerialDigest: sd, Reading: in, Since: time.Now()}
		s.judge(zone, z.Active, &h)
		i := slices.IndexFunc(z.Held, func(o heldSerial) bool { return CompareSerial(o.Serial, sd.Serial) > 0 })
		if i < 0 {
			i = len(z.Held)
		}
		z.Held = slices.Insert(z.Held, i, h)
		return nil
	})
}

// readingAt is the instructions this agent holds at sd, the zone named in
// any case: its active serial, a newer one, the serial it was thawed from,
// or its last thaw's from-serial (the instructions RFI's answer, plan S7);
// nil when it holds none with that digest.
func (s *InstructionStore) readingAt(zone string, sd SerialDigest) *Instructions {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, z := s.zoneLocked(zone)
	if z == nil {
		return nil
	}
	if h := z.held(sd.Serial); h != nil && h.SerialDigest == sd {
		return h.Reading
	}
	for _, h := range []*heldSerial{z.From, z.LastFrom} {
		if h != nil && h.SerialDigest == sd {
			return h.Reading
		}
	}
	return nil
}

// Done ends the zone's transition (S12): at the leader once every part
// holds its last step, at a member on the leader's first-hand stamp that
// shows it done. The from-serial, the step and its sets, and every removal
// still held go.
func (s *InstructionStore) Done(zone string) error {
	return s.update(zone, func(z *zoneSerials) error {
		if !z.reconciling() {
			return nil
		}
		z.From, z.Removals = nil, nil
		z.Step, z.Sets, z.StepOf, z.StepWhat, z.Taken, z.StepAt, z.Pending = 0, nil, 0, "", nil, time.Time{}, false
		z.Excused, z.DoneAt = nil, time.Now()
		return nil
	})
}

var errNotSteady = errors.New("the zone is not steady at this agent")

// Forget clears a zone's stored serials (design rule 3, the one exception to
// never giving a serial up). It is for a steady zone only, a refused newest
// serial included: it refuses one that agrees, reconciles, holds a removal or
// an owner error. The check and the drop are one step under the store's
// lock, so no copy noted between them is lost.
func (s *InstructionStore) Forget(zone string) error {
	if s == nil {
		return fmt.Errorf("this daemon keeps no serials")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	z := s.zones[zone]
	if z == nil {
		return fmt.Errorf("zone %s: no serials kept", zone)
	}
	if p := z.phase(); p != PhaseSteady && p != PhaseRefused {
		return fmt.Errorf("zone %s: %w (%s)", zone, errNotSteady, p)
	}
	return s.forgetLocked(zone)
}

// forgetLocked drops zone's serials, on disk and in memory. Called with s.mu
// held.
func (s *InstructionStore) forgetLocked(zone string) error {
	if err := s.persist(zone, nil); err != nil {
		return err
	}
	delete(s.zones, zone)
	delete(s.warnedOld, zone)
	for k := range s.refusedLogged {
		if k.zone == zone {
			delete(s.refusedLogged, k)
		}
	}
	return nil
}

// Prune drops the serials of every zone that keep says has left the
// configuration (design rule 3).
func (s *InstructionStore) Prune(keep func(zone string) bool) {
	if s == nil {
		return
	}
	// a frozen zone that leaves ends its freeze: its signer lets the hold go
	// (onFreeze), told once the lock is let go
	var thawed []string
	defer func() {
		for _, zone := range thawed {
			if s.onFreeze != nil {
				s.onFreeze(zone, false)
			}
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	for zone, z := range s.zones {
		if keep(zone) {
			continue
		}
		lg.Info("the zone left the configuration; its serials go with it", "zone", zone)
		frozen := len(z.freezeReasons()) > 0
		if err := s.forgetLocked(zone); err != nil {
			lg.Error("the serials of a zone that left the configuration could not be dropped", "zone", zone, "err", err)
			continue
		}
		if frozen {
			thawed = append(thawed, zone)
		}
	}
}

// activeReading is the zone's active instructions as the readers act by
// them, or nil when the store keeps none for it or keeps a record from
// before S7, which is not enforced: the readers act by the copy until Note
// enforces it (plan S7).
func (s *InstructionStore) activeReading(zone string) *Instructions {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if z := s.zones[zone]; z != nil && z.Active != nil && z.Enforced {
		return z.Active.Reading
	}
	return nil
}

// transition is the zone's transition as the store holds it: the
// from-serial's instructions (nil at rest), the active ones, and the step;
// to is nil when the store keeps none for the zone or does not enforce it
// yet (activeReading).
func (s *InstructionStore) transition(zone string) (from, to *Instructions, step int) {
	if s == nil {
		return nil, nil, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	z := s.zones[zone]
	if z == nil || z.Active == nil || !z.Enforced {
		return nil, nil, 0
	}
	if z.From != nil {
		from = z.From.Reading
	}
	return from, z.Active.Reading, z.Step
}

// removal is the zone's removal under way of the provider with the label or
// the identity, if the store holds one (S12, S17b fill them): a provider
// whose removal is under way is resolved through its stored identity
// (design 3.3).
func (s *InstructionStore) removal(zone, label, identity string) (Removal, bool) {
	if s == nil {
		return Removal{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if z := s.zones[zone]; z != nil {
		for _, r := range z.Removals {
			if (label != "" && r.Label == label) || (identity != "" && core.EqualNames(r.Identity, dns.Fqdn(identity))) {
				return r, true
			}
		}
	}
	return Removal{}, false
}

// InstructionsStatus is what the agent keeps of a zone's instructions, as
// `agent parentsync status`, `zone mplist` and the auditor show it.
type InstructionsStatus struct {
	Phase    string        `json:"phase"`
	Active   *SerialDigest `json:"active,omitempty"`
	Newest   *SerialDigest `json:"newest,omitempty"`
	Agreeing *SerialDigest `json:"agreeing,omitempty"` // the serial agreed on
	// Refused is the newest serial's refusal, against the active serial;
	// until S7, against the serial it followed.
	Refused    []Refusal     `json:"refused,omitempty"`
	Copy       SerialDigest  `json:"copy"`
	CopyError  string        `json:"copy_error,omitempty"`
	From       *SerialDigest `json:"from,omitempty"`
	LastThaw   *Thaw         `json:"last_thaw,omitempty"`
	OwnerError string        `json:"owner_error,omitempty"`
	Enforced   bool          `json:"enforced"`
	Removals   []Removal     `json:"removals,omitempty"`
	// The reconciliation's step held here, the steps planned and what it
	// does (S12); and when the last transition was done.
	Step     int       `json:"step,omitempty"`
	StepOf   int       `json:"step_of,omitempty"`
	StepWhat string    `json:"step_what,omitempty"`
	DoneAt   time.Time `json:"done_at,omitzero"`
	// Thaw is what the agreement waits for, the reconciliation's step and
	// what it waits for, or the last transition done here (instr_thaw.go,
	// reconcile.go, plans S7 and S12); the agent's to fill.
	Thaw string `json:"thaw,omitempty"`
}

// Status is the zone's kept serials, or nil when none are kept.
func (s *InstructionStore) Status(zone string) *InstructionsStatus {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	z := s.zones[zone]
	if z == nil {
		return nil
	}
	st := &InstructionsStatus{
		Phase:      z.phase(),
		Copy:       z.Copy,
		CopyError:  z.CopyError,
		LastThaw:   z.LastThaw,
		OwnerError: z.OwnerError,
		Enforced:   z.Enforced,
		Removals:   slices.Clone(z.Removals),
		Step:       z.Step,
		StepOf:     z.StepOf,
		StepWhat:   z.StepWhat,
		DoneAt:     z.DoneAt,
	}
	if z.Active != nil {
		a := z.Active.SerialDigest
		st.Active = &a
	}
	if h := z.highest(); h != nil {
		n := h.SerialDigest
		st.Newest = &n
		st.Refused = slices.Clone(h.Refused)
	}
	if a := z.agreeing(); a != nil {
		ag := a.SerialDigest
		st.Agreeing = &ag
	}
	if z.From != nil {
		f := z.From.SerialDigest
		st.From = &f
	}
	return st
}

// Line is the status in one line, as `agent parentsync status` prints it: a
// refusal or an owner error first, and last what the thaw waits for, or the
// last thaw. A record kept before S7 is not enforced: the readers act by the
// copy (activeReading).
func (st *InstructionsStatus) Line() string {
	if st == nil {
		return "none kept"
	}
	if st.OwnerError != "" {
		line := "held: owner error: " + st.OwnerError
		if !st.Enforced {
			line += "; not enforced"
		}
		return line
	}
	var parts []string
	if st.Active != nil {
		parts = append(parts, "active "+st.Active.String())
	}
	if st.From != nil {
		parts = append(parts, fmt.Sprintf("thawed from %d", st.From.Serial))
	}
	if a := st.Agreeing; a != nil && (st.Newest == nil || *a != *st.Newest) {
		parts = append(parts, "agreeing on "+a.String())
	}
	if st.Newest != nil && (st.Active == nil || *st.Newest != *st.Active) {
		parts = append(parts, "newest "+st.Newest.String())
	}
	parts = append(parts, fmt.Sprintf("copy %d", st.Copy.Serial))
	line := strings.Join(parts, ", ")
	if r := st.refusedLine(); r != "" {
		line = r + "; " + line
	}
	switch {
	case st.Thaw != "":
		line += "; " + st.Thaw
	case st.Phase != PhaseSteady && st.Phase != PhaseRefused:
		line += "; " + st.Phase
	}
	if !st.Enforced {
		line += "; not enforced"
	}
	return line
}

// refusedLine is the newest serial's refusal, "42 refused: ...", or "".
func (st *InstructionsStatus) refusedLine() string {
	if len(st.Refused) == 0 || st.Newest == nil {
		return ""
	}
	return fmt.Sprintf("%d refused: %s", st.Newest.Serial, refusalText(st.Refused))
}

// fillMPZoneInfo adds the zone's kept serials to its mplist row.
func (s *InstructionStore) fillMPZoneInfo(zone string, info *MPZoneInfo) {
	st := s.Status(zone)
	if st == nil {
		return
	}
	info.Active, info.Newest = st.Active, st.Newest
	info.Refused = st.refusedLine()
	if info.OwnerError == "" {
		info.OwnerError = st.OwnerError
	}
}

// noteInstructions has the store classify the zone's copy as a refresh left
// it, at the first load and at every refresh (the post-refresh callback).
func (conf *Config) noteInstructions(mpzd *MPZoneData) {
	s := conf.InternalMp.Instructions
	if s == nil {
		return
	}
	apex, err := mpzd.OwnerForAnalysis(mpzd.ZoneName)
	if err != nil || apex == nil {
		return
	}
	in, err := ReadInstructions(apex)
	s.Note(mpzd.ZoneName, in, err)
}

// onSetsChanged applies the step's sets where they act beyond the readers
// (plan S3): the parentsync option, both ways, which tdns's parentsync hook
// (P3) reads through the sets too; and with recompute, the multi-provider
// data, MPOptions and the combiner's allow-edits, so that a change of the
// sets takes effect without a transfer. A refresh calls it without
// recompute: its pre-refresh analysis has computed them from the incoming
// copy, whose reading is the active one until S7. S12 calls it with
// recompute at every step.
func (conf *Config) onSetsChanged(mpzd *MPZoneData, recompute bool) (givenBack bool) {
	if recompute && mpzd.Options[tdns.OptMultiProvider] {
		mpzd.populateMPdata(conf.MpConfig(), nextSigningSetOf(mpzd.instructions(), mpzd.signingSet()))
	}
	givenBack = conf.followParentSyncParam(mpzd)
	conf.handOverToParts(mpzd.ZoneName) // the agent's combiner and signer act by the sets too (S10, S11)
	return givenBack
}
