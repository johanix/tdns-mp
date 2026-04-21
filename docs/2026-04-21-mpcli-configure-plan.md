# mpcli configure — Planning Doc

Date: 2026-04-21
Status: Draft, pre-implementation

## Motivation

Setting up a working tdns-mp deployment requires coordinated
configuration across four YAML files:

- `tdns-mpagent.yaml`
- `tdns-mpsigner.yaml`
- `tdns-mpcombiner.yaml`
- `tdns-mpcli.yaml`

Roughly 8–10 primary decisions cascade into all four files:
role identities (agent/signer/combiner FQDNs), API keys, JOSE
keypair paths, TLS cert paths, port allocation, peer addresses.
Getting any of these out of sync silently breaks the system in
ways that are hard to diagnose.

A guided configurator reduces this from "read four sample
configs carefully" to answering a sequence of prompts.

## Decision: subcommand of mpcli

Rejected alternatives:

- **Separate tool (5th binary)**: cleaner layering but adds
  build/install/document burden for a mostly-bootstrap operation.
- **`--configure` flag on each server**: would require running
  each server three times and still couldn't emit mpcli.yaml.

Chosen: `tdns-mpcli configure`.

Layering smell acknowledged — mpcli becomes responsible for
generating configs for apps it doesn't run — but centralisation
benefit outweighs it, and mpcli is already the operator-facing
tool users have in hand.

## Behaviour

### First run

Interview the user for the coordinated knobs. Generate all four
YAMLs from templates, write atomically.

### Re-run

Read all four existing YAMLs. Prompt with current values as
defaults. Emit diffs. On confirmation, write atomically.

### JOSE keys

Default: **reuse existing keypairs**. Rotating keys is a
separate operation with peer-visible consequences (pubkey must
be redistributed) and must not happen as a side effect of
"change a port." A rotation is a distinct, explicit action —
out of scope for this doc.

## Safeguards

Each of these applies independently; all are cheap and stack.

### 1. Backup before write

Always rename existing `foo.yaml` to `foo.yaml.bak.<timestamp>`
before emitting a new one. No prompt, no flag — unconditional.

### 2. Diff preview

Before any write, show a unified diff of pending changes per
file. Single top-level confirmation ("apply these changes to 3
files? [y/N]") gates all writes.

### 3. Atomic write + re-parse

Write the new YAML to a tempfile in the same directory, parse it
back to validate syntax, then `rename(2)` into place. A crashed
or killed configurator never leaves a half-written config.

### 4. Live-server gate

Before touching a server config, ping its API. If the server
responds, refuse to proceed without a typed confirmation string
per live server (e.g. `yes, reconfigure mpagent`). A bare `-y`
or `--force` is insufficient for this gate — the typing
requirement is the whole point.

Non-responsive servers pass the gate silently; the diff preview
still applies.

### Generation of missing material

When a path is configured but the file does not exist, the
configurator generates it:

- **JOSE keypairs**: generate if missing. Reuse if present.
  *Rotation* (overwriting an existing keypair) is a separate
  command, out of scope here.
- **TLS certs**: generate if missing, using the existing local
  cert generator at `tdns/utils/gen-cert.sh` (+ `openssl.cnf`).
  Reuse if present. Same reuse-vs-rotate distinction as JOSE.
- **API keys**: generate strong random keys if missing. Display
  once, persist into the relevant configs. Reuse if present.

### Out of scope

- **Scope flags** (`--only mpagent`, `--exclude mpcli`): rejected
  as over-engineering for a tool run occasionally. The diff +
  confirmation flow already prevents untouched files from being
  rewritten.
- **Key/cert rotation**: separate command, separate design.
- **First-run defaults**: none. Prompt every field on first run.
  If this proves unwieldy in practice, revisit — do not
  pre-optimise.

## Implementation sketch

Phases (rough, not committed):

1. Config read/write plumbing — parse all four YAMLs into typed
   structs, round-trip without losing comments if feasible
   (otherwise accept comment loss and document it).
2. Interview engine — prompt/default/validate per field, with
   live-server ping integrated.
3. Diff + atomic write machinery.
4. Generation of missing material: JOSE keypairs, TLS certs
   (via `tdns/utils/gen-cert.sh`), API keys.
5. End-to-end first-run flow.
6. Re-run flow with live-server gate.
