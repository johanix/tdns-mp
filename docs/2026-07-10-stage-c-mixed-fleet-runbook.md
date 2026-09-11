# Stage C mixed-fleet runbook

Date: 2026-07-10
Status: OPERATIONAL PROCEDURE. This is the C0.3 gate item (v3 plan /
road-to-C Phase 4): the one-page procedure for running a fleet where some
nodes carry Stage-C commits and some do not. Read it before deploying ANY
C-stage commit, and follow it for every C-stage deploy until the stage
exit gate.

## Why Stage C is the risky stage

Stage C relocates payload types (C4/C6), collapses the send path (C2),
and moves receive handlers (C3/C5). Every step is INTENDED to be
wire-identical — the golden-wire suite (`golden_wire_test.go` +
`testdata/golden-wire/`) enforces byte-exact tags, values, and the verb
set in CI. The residual risk is the failure the goldens cannot see:
behavioral drift in dispatch (a message that delivers but no longer
reaches its handler on the OTHER side of a version boundary).

## The wire contract a mixed fleet relies on

1. **The verb is the JSON payload key `"MessageType"`** (legacy `"type"`
   as fallback). Carrier-struct/Go-type names are wire-irrelevant.
2. **`parsePayload` strictness** (`chunk_notify_handler.go` ~:270): a
   message with BOTH `MessageType` and `type` set to DIFFERENT values is
   REFUSED (M21 anti-ambiguity), as is a `Zone`/`zone` conflict. A
   half-migrated sender that changes one twin but not the other produces
   messages every receiver rejects — this is the loudest mixed-fleet
   failure and the easiest to hit by accident.
3. **Unknown verbs dead-end**: `DetermineMessageType` returns UNKNOWN
   and the message is dropped after delivery. A renamed verb therefore
   fails SILENTLY on un-upgraded receivers (delivered-but-not-dispatched).
4. **Additive JSON fields are safe** (unknown fields are ignored on
   decode); REMOVED or RENAMED fields/tags are not. The only planned
   additive change is C5's `envelope` label (absent ⇒ `jose`); the only
   planned BREAKING change is F1 (`Gossip`→`AppData`), which is
   explicitly fleet-coordinated and NOT part of Stage C.

## Deploy order (per C-stage step)

1. **Never deploy a C-stage commit fleet-wide in one shot.** Upgrade ONE
   observer agent first (by convention: cpt — the node whose logs you
   watch). Combiner/signer upgrade LAST within any step that touches
   their role routers (C3) or the chunk path (C5); for other steps they
   can lag indefinitely.
2. Let the mixed pair (upgraded cpt ↔ un-upgraded fox/hare) run at least
   two beat intervals plus one real exchange:
   - `gossip state -z <zone>` — matrix must stay fully OPERATIONAL.
   - one `zone edits`-style distribution (SYNC out, CONFIRM back).
   - one RFI round-trip.
   - combiner path: one update reaching the combiner + async confirm.
3. Only after the mixed pair is clean: roll the remaining agents, then
   combiner/signer.

## Observable symptoms of a wire break (what to watch)

| Symptom | Likely cause |
|---|---|
| `conflicting message type fields: MessageType=... vs type=...` in receiver log | half-migrated twin fields (M21 refusal) — the sender's C-commit changed one twin |
| sender logs "delivered"/NOERROR but receiver never logs the handler | verb drift: `DetermineMessageType` → UNKNOWN on the receiver |
| beats flow but SYNC/RFI/KEYSTATE stop across the version boundary | app-verb routing moved (C3/C5) without the compat shim |
| peers decay to DEGRADED/INTERRUPTED only across the version boundary | hello/beat payload field drift (should be impossible — goldens) |
| `no message type found in payload` | payload serialized without either verb twin |

First diagnostic in every case: capture the payload bytes on both sides
(sender pre-encrypt log / receiver post-decrypt log) and diff against
`testdata/golden-wire/<Type>.json`.

## Rollback

Every C-stage step is one commit on the stage branch, wire-compatible by
construction. Rollback = redeploy the previous commit's binaries on the
UPGRADED node(s) only — never "fix forward" on the un-upgraded nodes.
The peer state stores tolerate restarts (rediscovery + beats reconverge);
after rollback, verify the same probe set as step 2 above. If the fault
was M21 refusals, expect immediate reconvergence; if it was silent verb
drift, expect one beat interval before the matrix heals.

## Standing rules

- The golden-wire suite MUST pass before any C-stage commit is pushed;
  intentional wire changes regenerate goldens via
  `go test -run TestGoldenWire -update ./...` and the diff is reviewed
  in the same commit.
- Exercise BOTH chunk modes (edns0 and query) in the step-2 probes for
  any step touching the chunk path (C5, and C3 for role routers).
- The fleet is DNS-only today: any API-mechanism observation during a
  C-stage deploy is itself an anomaly worth stopping for.
