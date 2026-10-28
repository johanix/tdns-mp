/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * The judge (design 3.1, plan S4): whether a change of the zone's
 * instructions from one serial to another may be carried out. It is a
 * function of the two serials alone, so every agent judges alike and gives
 * the same reason.
 */
package tdnsmp

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	core "github.com/johanix/tdns/v2/core"
)

// The judge's codes (plan S4), in the order the judge lists them. From S5a
// an agent tells its refusal by its code.
const (
	RefusedRecordWithRoleRemoved = "record-with-role-removed"
	RefusedRoleWithoutRecord     = "role-without-record"
	RefusedIdentityChanged       = "identity-changed"
	RefusedSignerToServer        = "signer-to-server"
	RefusedSignersEmptied        = "signers-emptied"
	RefusedUpstreamDangling      = "upstream-dangling"
	RefusedUpstreamSignerRemoved = "upstream-signer-removed"
	RefusedStepMissing           = "step-missing"
	RefusedNotBuilt              = "not-built"
)

var refusalRank = map[string]int{
	RefusedRecordWithRoleRemoved: 1, RefusedRoleWithoutRecord: 2, RefusedIdentityChanged: 3,
	RefusedSignerToServer: 4, RefusedSignersEmptied: 5, RefusedUpstreamDangling: 6,
	RefusedUpstreamSignerRemoved: 7, RefusedStepMissing: 8, RefusedNotBuilt: 9,
}

// Refusal is one reason the judge refuses a transition: its code, and the
// reason as the status shows it.
type Refusal struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// refusalText is a serial's refusal in one line: its first reason, the most
// basic, and how many more there are.
func refusalText(rs []Refusal) string {
	switch len(rs) {
	case 0:
		return ""
	case 1:
		return rs[0].Reason
	}
	return fmt.Sprintf("%s (and %d more)", rs[0].Reason, len(rs)-1)
}

// changeKind is a kind of change that needs steps of its own (design 5).
type changeKind uint

const (
	kindRolesTaken changeKind = 1 << iota // a role taken away: S17b
	kindServerRole                        // a server role given: S18a
	kindSignerRole                        // a move into signers=: S18b, with P5
	kindNSmgmt                            // S19
	kindParentSync                        // S20
	kindUpstream                          // an upstream changed: S21
	kindPubkey                            // pubkey or pubcds: S21
)

// builtKinds are the kinds whose steps are built (decision 29), and
// carriedKinds the kinds whose step can be carried out at all: a signer role
// needs P5, an upstream its agent's check of the new transfer (S21). Each
// step that builds a kind adds it here; the judge reads no config.
const (
	builtKinds   changeKind = 0
	carriedKinds changeKind = kindRolesTaken | kindServerRole | kindNSmgmt | kindParentSync | kindPubkey
)

// judgeTransition judges the change from the instructions at one serial to
// those at another. from is the active serial, or for a member that moves
// straight on a thaw, the thaw's from-serial (design 3.1). No refusal: the
// change is agreed.
func judgeTransition(from, to *Instructions) []Refusal {
	return judge(from, to, builtKinds, carriedKinds)
}

func judge(from, to *Instructions, built, carried changeKind) []Refusal {
	if from == nil || to == nil {
		return nil
	}
	j := &judgement{from: from, to: to}
	fServers, fSigners := judgedRoles(from)
	tServers, tSigners := judgedRoles(to)
	roleIn := func(servers, signers []string, label string) bool {
		return slices.Contains(servers, label) || slices.Contains(signers, label)
	}

	// The records of the labels with a role, under either serial: records
	// are matched by label and identity (S1).
	labels := slices.Concat(fServers, fSigners, tServers, tSigners)
	slices.Sort(labels)
	for _, label := range slices.Compact(labels) {
		fRole, tRole := roleIn(fServers, fSigners, label), roleIn(tServers, tSigners, label)
		f, inFrom := from.record(label)
		t, inTo := to.record(label)
		given := !slices.Contains(fServers, label) && slices.Contains(tServers, label) ||
			!slices.Contains(fSigners, label) && slices.Contains(tSigners, label)
		switch {
		case fRole && inFrom && !inTo:
			j.refuse(RefusedRecordWithRoleRemoved, "removes the record of %s, which has a role under %d", f.Identity, from.Serial)
		case given && !inFrom:
			j.refuse(RefusedRoleWithoutRecord, "gives a role to %s, which has no record under %d", j.name(label), from.Serial)
		case given && !inTo:
			j.refuse(RefusedRoleWithoutRecord, "gives a role to %s, whose record it removes", j.name(label))
		case (fRole || tRole) && inFrom && inTo && !core.EqualNames(f.Identity, t.Identity):
			j.refuse(RefusedIdentityChanged, "changes the identity under %s, which has a role, from %s to %s", label, f.Identity, t.Identity)
		}
	}

	for _, label := range fSigners {
		if !slices.Contains(tSigners, label) && slices.Contains(tServers, label) {
			j.refuse(RefusedSignerToServer, "moves the signer %s to servers= only", j.name(label))
		}
	}
	if len(fSigners) > 0 && len(tSigners) == 0 {
		j.refuse(RefusedSignersEmptied, "empties signers=, which lists %s under %d", strings.Join(fSigners, ","), from.Serial)
	}
	for _, r := range to.Records {
		if r.Upstream == "" {
			continue
		}
		if !slices.Contains(tSigners, r.Upstream) {
			j.refuse(RefusedUpstreamDangling, "the upstream of %s names %s, which is not in signers= under %d", r.Identity, r.Upstream, to.Serial)
		} else if _, ok := to.record(r.Upstream); !ok {
			j.refuse(RefusedUpstreamDangling, "the upstream of %s names %s, which has no record under %d", r.Identity, r.Upstream, to.Serial)
		}
	}
	for _, r := range from.Records {
		if r.Upstream != "" && slices.Contains(fServers, r.Label) && slices.Contains(tServers, r.Label) &&
			slices.Contains(fSigners, r.Upstream) && !slices.Contains(tSigners, r.Upstream) {
			j.refuse(RefusedUpstreamSignerRemoved, "takes %s out of signers=, while it is the upstream of the server %s under %d", j.name(r.Upstream), r.Identity, from.Serial)
		}
	}

	// The kinds of change that need steps of their own: refused while their
	// step cannot be carried out, or is not built.
	kind := func(k changeKind, what string, args ...any) {
		switch {
		case carried&k == 0:
			j.refuse(RefusedStepMissing, what+", a step that cannot be carried out yet", args...)
		case built&k == 0:
			j.refuse(RefusedNotBuilt, what+": not built yet", args...)
		}
	}
	for _, label := range setMinus(fServers, tServers, fSigners, tSigners) {
		kind(kindRolesTaken, "takes a role from %s", j.name(label))
	}
	for _, label := range setMinus(tServers, fServers) {
		kind(kindServerRole, "gives %s a server role", j.name(label))
	}
	for _, label := range setMinus(tSigners, fSigners) {
		kind(kindSignerRole, "moves %s into signers=", j.name(label))
	}
	for _, f := range from.Records {
		if t, ok := to.record(f.Label); ok && core.EqualNames(f.Identity, t.Identity) && f.Upstream != t.Upstream {
			kind(kindUpstream, "changes the upstream of %s", f.Identity)
		}
	}
	if from.NSmgmt != to.NSmgmt {
		kind(kindNSmgmt, "changes nsmgmt")
	}
	if from.ParentSync != to.ParentSync {
		kind(kindParentSync, "changes parentsync")
	}
	if from.Pubkey != to.Pubkey {
		kind(kindPubkey, "changes pubkey")
	}
	if from.Pubcds != to.Pubcds {
		kind(kindPubkey, "changes pubcds")
	}

	slices.SortStableFunc(j.out, func(a, b Refusal) int { return cmp.Compare(refusalRank[a.Code], refusalRank[b.Code]) })
	return j.out
}

type judgement struct {
	from, to *Instructions
	out      []Refusal
}

func (j *judgement) refuse(code, format string, args ...any) {
	j.out = append(j.out, Refusal{Code: code, Reason: fmt.Sprintf(format, args...)})
}

// name names the provider under a label: by its identity under to, or else
// under from, or by its label when neither has a record for it.
func (j *judgement) name(label string) string {
	if r, ok := j.to.record(label); ok {
		return r.Identity
	}
	if r, ok := j.from.record(label); ok {
		return r.Identity
	}
	return "label " + label
}

// judgedRoles are the labels with a server role and with a signer role, as
// the parts act by them (rolesFor): without HSYNCPARAM, every ON record
// serves and none signs.
func judgedRoles(in *Instructions) (servers, signers []string) {
	if in.HasParam {
		return in.Servers, in.Signers
	}
	for _, r := range in.Records {
		servers = append(servers, r.Label)
	}
	return servers, nil
}

// record is the ON record under label.
func (in *Instructions) record(label string) (InstrRecord, bool) {
	i := slices.IndexFunc(in.Records, func(r InstrRecord) bool { return r.Label == label })
	if i < 0 {
		return InstrRecord{}, false
	}
	return in.Records[i], true
}

// setMinus is the sorted labels of each pair's first set that are not in its
// second: (a, b, c, d) is a\b ∪ c\d.
func setMinus(pairs ...[]string) []string {
	var out []string
	for i := 0; i+1 < len(pairs); i += 2 {
		for _, l := range pairs[i] {
			if !slices.Contains(pairs[i+1], l) {
				out = append(out, l)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
