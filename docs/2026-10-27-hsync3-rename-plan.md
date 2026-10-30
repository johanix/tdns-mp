# HSYNC3 becomes HSYNC: rename plan

**Status:** PLAN, 2026-10-27. Scope and decisions agreed by the project
owner on 2026-10-27; not scheduled, nothing implemented. Counted against
tdns main `c2809eff` and tdns-mp main `5f76ea8` (2026-10-27).

## 1. Goal

tdns's private record type HSYNC3 (type 65285) is the per-provider
enrollment record that the draft calls HSYNC. It takes that name:
first the mnemonic used in zone files and in every presentation (dog,
tdns-cli, the tdns-mp CLIs, logs), then the Go names in tdns, then the
Go names in tdns-mp.

HSYNCPARAM keeps its name, and so does the `use-hsyncparam` option.

## 2. What stays

- **The wire format and codepoint 65285, through steps 0 to 3.** No byte on
  the wire changes. Removing the State field and moving to a new codepoint
  is step 4, a separate step after step 2 (section 7).
- **Dated documents** in `docs/` of both repositories: they record their
  day. About 230 lines in tdns-mp and 60 in tdns mention HSYNC3; none is
  edited.
- **The v1 tree in tdns** (`tdns/`, `cmd/`): a separate module with its own
  HSYNC at another codepoint (0x0F9D). It is never linked beside v2.
- **tdns-transport** has no reference to HSYNC3.

## 3. The old HSYNC and HSYNC2 types

tdns v2 still defines HSYNC (65282) and HSYNC2 (65283), the first two
generations of the enrollment record, which HSYNC3 and HSYNCPARAM
replaced. HSYNC clashes with the new name twice:

- the mnemonic: both types would register `HSYNC` in
  `dns.StringToType`, and the later registration wins;
- the Go names: `core.HSYNC` and `core.TypeHSYNC` exist.

**Decision:** delete both types. `rr_defs.go` keeps 65282 and 65283 as
retired codepoints so that nothing reuses them.

tdns-mp still reads the old types as a fallback, in three places:

- `v2/hsync_utils.go`: our Label from an old record when no HSYNC3 matches,
  and the signing decision (`analyzeHsyncSigners`);
- `v2/hsync_utils.go` (`populateMPdata`) and `v2/combiner_chunk.go`: a zone
  with only old records counts as a multi-provider zone.

These go in step 0. With them goes one behaviour: a zone that has only
HSYNC or HSYNC2 records is no longer a multi-provider zone. No zone file in
tdns or tdns-mp uses the old records; only their own round-trip tests in
tdns do.

The constants that `rr_hsync.go` shares with the types that stay move
before the file goes: `HsyncStateON`/`OFF` with their maps (HSYNC3) and
`HsyncNSmgmtOWNER`/`AGENT` with their maps (HSYNCPARAM, and tdns-mp).
`HsyncSignYES`/`NO` is used only by the fallback and goes with it.

## 4. Steps

| Step | Repo | What | Lines |
|---|---|---|---|
| 0 | tdns-mp | Delete the HSYNC/HSYNC2 fallback (section 3). Needs no re-pin. | ~80 deleted |
| 1 | tdns | Mnemonic `HSYNC`; error strings; living docs; delete the HSYNC and HSYNC2 types and their tests | ~35 edited, ~760 deleted |
| 2 | tdns | Go names; `rr_hsync3.go` becomes `rr_hsync.go` (and its test) | ~50 |
| re-pin | tdns-mp | One re-pin over steps 1 and 2: text, then `core.*` names | ~305 |
| 3 | tdns-mp | tdns-mp's own names | ~410 |
| 4 | tdns, tdns-mp | State removed, new codepoint (section 7) | not sized |

Order: 0, 1, 2, re-pin, 3. Step 4 comes after step 2.

### Step 0: tdns-mp, the fallback

Delete the three readers of section 3 and their comments. It builds
against today's pin, so it can land at any time.

### Step 1: tdns, the mnemonic

- `v2/core/rr_hsync3.go`: `dns.PrivateHandle("HSYNC", TypeHSYNC3, ...)`
  and `dns.TypeToString`; the error strings ("HSYNC3 requires ...",
  "invalid HSYNC3 ..."); the zone-file syntax comment.
- Delete `v2/core/rr_hsync.go` and `v2/core/rr_hsync2.go`, after moving
  the shared constants; delete their round-trip tests in
  `v2/core/rr_parse_test.go` (about 150 lines); retire the two
  codepoints in `rr_defs.go`.
- Living docs: `NEW-RRTYPES.md` (its HSYNC and HSYNC2 sections go),
  `guide/app-dog.md`, `guide/special-features.md`, `cmdv2/dog/README.md`,
  `docs/open-items.md`.

dog and tdns-cli print record types through `dns.TypeToString`, so they
show the new name with no change of their own.

### Step 2: tdns, the Go names

`HSYNC3` → `HSYNC`, `TypeHSYNC3` → `TypeHSYNC`, `NewHSYNC3` → `NewHSYNC`,
`RegisterHsync3RR` → `RegisterHsyncRR`, `checkHsync3Label` and
`checkHsync3Upstream`, the test helpers, the comments. The names are free
once step 1 has deleted the old type. About 50 lines.

Steps 1 and 2 land as two tdns PRs, back to back.

### Re-pin: tdns-mp, once over steps 1 and 2

tdns-mp's tests parse zone text that says HSYNC3. After step 1 that text
no longer parses, so the re-pin that takes step 1 carries the text change.
Re-pinning once over steps 1 and 2 does the text and the `core.*` names
in one PR:

- zone text in tests: `v2/leaving_signer_test.go`,
  `v2/cli/configure/examplezone_test.go`,
  `v2/cli/agent_parentsync_cmds_test.go`,
  `v2/signer_relayed_serial_test.go`,
  `v2/combiner_signal_consent_test.go` (about 25 lines);
- the example zone template
  `v2/cli/configure/templates/mptest.example.zone.tmpl` and
  `tests/mp-policy-matrix/gen.py`;
- what a user reads: log lines, errors and CLI output (about 70 lines);
- `guide/`, `README.md`, the sample configs and the configure templates
  (about 115 lines);
- `core.HSYNC3` → `core.HSYNC` and `core.TypeHSYNC3` → `core.TypeHSYNC`:
  about 105 lines in 33 files, mechanical;
- `go.mod` and `go.sum` in the six modules.

### Step 3: tdns-mp, its own names

About 30 identifiers of tdns-mp's own that contain hsync3
(`seedZoneWithHSYNC3`, `OnHsync3Changed`, `normalizeHSYNC3Label`,
`hsync3IdentitiesByLabel`, the test names, ...): about 185 code lines and
225 comment lines.
`v2/hsync/hsync3_diff.go` and `v2/hsync/hsync3_test.go` are renamed.

Mostly mechanical, with these by hand:

- `v2/agent_utils.go:206` (at `5f76ea8`): a local variable `hsync3`
  becomes `hsync` under a plain replace, and hides the package `hsync`,
  which the same block calls (`hsync.NewPeer`). It needs another name.
- The auditor's JSON field `hsync3_state` (`v2/auditor_mplist.go`) is
  renamed. It is a CLI-to-daemon field; no compatibility is kept.

"Hsync" already names the subsystem (the package `hsync`, `HsyncEngine`,
`HsyncDB`, `HsyncChanged`), and much of the record handling already says
Hsync (`ApplyHsyncDiff`, `hsyncRRset`). After step 3 the record and the
subsystem share the name. Accepted.

## 5. What breaks, and is accepted

- **No alias for the old name.** After step 1, a zone file that says
  HSYNC3 does not load; it is rewritten with the new name. (An alias would
  be one line, `dns.StringToType["HSYNC3"] = TypeHSYNC`; it is not added.)
- **One build everywhere.** Every agent, combiner, signer and auditor runs
  the same build, as always. End-to-end tests outside this repository that
  write zone files, or match HSYNC3 in output, switch together with the
  build they test.

## 6. Scheduling

Open branches that add HSYNC3 code conflict with the re-pin and with step
3. At `5f76ea8`, #280 and #281 (S1 and S2 of the owner-instruction plan)
each add about 50 such lines; #178 adds about 35 in documents. The
owner-instruction plan's later steps will add more, so step 3 grows the
longer it waits. Steps 0, 1 and 2 conflict with nothing open: no open
tdns-mp branch touches step 0's lines, and no open tdns branch touches
the files of steps 1 and 2.

## 7. Step 4: State and the codepoint

The draft's HSYNC has no State field; tdns's HSYNC3 has one. Removing it
changes the wire format, so the record moves to a new codepoint and every
agent switches at once. About 20 lines in tdns-mp read State, and tests
that publish a record with State OFF need another way to say it. Until
step 4, tdns's HSYNC carries a field that the draft has dropped.

**Decision (2026-10-27):** a separate step after step 2, so that steps 0
to 3 stay mechanical and leave the wire alone.

## 8. Decisions, 2026-10-27

1. The old HSYNC and HSYNC2 types are deleted, not renamed.
2. tdns steps 1 and 2 land back to back; tdns-mp re-pins once over both.
3. No alias for the old mnemonic.
4. Tests outside this repository switch together with the build.
5. Step 3's hand fixes, and one name for the record and the subsystem.
6. The JSON field `hsync3_state` is renamed.
7. State and the codepoint are step 4, after step 2.
