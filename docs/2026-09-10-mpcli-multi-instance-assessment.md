# Addressing several mp daemons of one role from tdns-mpcli — assessment

Date: 2026-09-10
Status: ASSESSMENT with a plan; nothing implemented.
Context: the scenario rigs (`2026-09-10-mp-scenario-test-rigs-design.md`)
run three providers on one host. With today's `tdns-mpcli` a human
addresses provider 2's agent as
`tdns-mpcli --config /var/tmp/mp-policy-matrix/p2/tdns-mpcli.yaml agent …`,
one complete CLI config per provider and `--config` on every command.
tdns has solved this for `tdns-auth` with `tdns-ncli`
(`tdns/docs/2026-09-07-cli-multi-instance-design.md`):

```
tdns-ncli auth    zone list      # canonical instance
tdns-ncli sectdns zone list      # second instance, from one apiservers entry with role: auth
```

The question: can the same mechanism reasonably be adapted for
tdns-mpcli, so that a rig user types

```
tdns-mpcli p1-agent    zone mplist
tdns-mpcli p2-combiner zone edits list -z p2s1a.rig.test.
tdns-mpcli p2-signer   keystore dnssec list -z p2s1a.rig.test.
tdns-mpcli aud         zones
```

with one `tdns-mpcli.yaml` naming all eleven daemons?

**Answer: yes, and it is mostly mechanical; about two to three days.
One thing is not free: the mechanism lives in tdns `v2/cli` at a
version tdns-mp does not pin, so the ~300 lines of mechanism have to be
carried in tdns-mp until the re-pin.** Details below.

## 1. How tdns-ncli does it

Three pieces, all in tdns `v2/cli` on main since 2026-09-07
(`527b09ed`, `d9071e65`):

1. **A tree is a second instantiation, not a second definition.** The
   auth tree was already built from role-parameterised factories
   (`NewZoneCmd(role)`, `NewKeystoreCmd(role)`, …). `NewAuthTree(use,
   role)` (`auth_tree.go`) calls the same factories once more with a
   different role. A `*cobra.Command` has exactly one parent, which is
   the only reason new command objects are needed at all.
2. **The target is read off the command tree, not threaded.**
   `role_target.go`: `TagRole(root, role)` stores the role as a cobra
   annotation on the tree root; `GetApiClientForCmd(cmd, …)` walks up
   from any command to find it. Closures get their `*cobra.Command`
   for free, so this cannot be forgotten the way a threaded parameter
   was — 24 sites in tdns had hardcoded `GetApiClient("auth")`, which
   under a second instance silently drives the wrong daemon. An
   untagged tree is an error, never a default.
3. **Instances come from config, early.** `instances.go`: one optional
   `role:` field on an `apiservers:` entry; the entry's `name` becomes
   both the command word and the clientKey (`RegisterRole(name, name)`,
   `root.AddCommand(NewAuthTree(name, name))`). Because a command word
   must exist before cobra's `Find()`, the `apiservers:` block is read
   best-effort before `Execute()` (`EarlyApiServers`,
   `ConfigPathFromArgs`); the authoritative config load still happens
   in `PersistentPreRun`. Name collisions with built-in roles, earlier
   entries, `help`/`completion`/`show-cmds` are refused with a message.

Only `auth` has a tree factory today (`knownInstanceRoles`); the
design says agent/imr "become the same conversion the day one is
wanted". mp's four roles are that day.

## 2. What tdns-mpcli looks like now

- `cmd/mpcli/shared_cmds.go` wires four static trees (`AgentCmd`,
  `CombinerCmd`, `SignerCmd`, `AuditorCmd`) with 50 `AddCommand` lines,
  roughly half from tdns factories that already take a role
  (`NewPingCmd`, `NewStopCmd`, `NewDaemonCmd`, `NewDebugCmd`,
  `NewConfigCmd`, `NewZoneCmd`, `NewKeystoreCmd`, `NewTruststoreCmd`)
  and from mp's own five factories (`NewGossipCmd`, `NewPeerCmd`,
  `NewKeysCmd`, `NewAuditorPeer{List,Zones}Cmd`).
- The rest of mp's tree is **117 package-level `var xxxCmd =
  &cobra.Command{…}`** across ~20 files, attached in `init()`s: the
  four role roots, `distrib`, `transaction`, `hsync` (11 leaves),
  `router` (18), the agent debug tree (12), combiner `edits`/`config`/
  `peer`, the auditor `eventlog`/`zones`/`observations`/`web` leaves,
  and the mp zone subcommands (`mplist`, `addrr`, `delrr`, `edits`,
  `bump`, …) that `init()` pushes into tdns's static `cli.AgentZoneCmd`.
- **29 sites hardcode the role**: `GetApiClient("agent")` ×20ish,
  `"combiner"` ×8, `"signer"`, `"auditor"`. Same latent defect as
  tdns's 24: invisible with one instance per role, wrong-target with
  two. None uses `GetApiClientForCmd` (it does not exist in the pinned
  tdns).
- Role→clientKey is already the tdns indirection: `roles.go` does
  `RegisterRole("agent", "tdns-mpagent")` etc.; `tdns-mpcli.yaml`
  `apiservers:` entries are keyed by that name. So the config shape
  extends exactly as in tdns: add `role:` to an entry and name it.

## 3. The pin problem

tdns-mp pins `github.com/johanix/tdns/v2/cli v0.0.0-20260611090745`
(June 11). `role_target.go`, `instances.go`, `ApiDetails.Role`,
`NewAuthTree` and `MergeViperIncludes` are all later. Three ways out:

| Option | What | Verdict |
|---|---|---|
| A. bump only the `tdns/v2/cli` module | `v2/cli` is its own Go module; its published go.mod requires the placeholder `tdns/v2 v2.0.0-00010101…` (local replace), so MVS would keep mp's June `tdns/v2` while taking a September `cli` | Ten-minute experiment, but the September cli code is written against the September lib (`MergeViperIncludes`, the delsync renames, …) and will most likely not compile against the June lib. Even if it does, it is half of F0 through the back door. Not recommended. |
| B. carry the mechanism in tdns-mp | copy `role_target.go` (115 lines) and `instances.go` (188 lines) into `tdns-mp/v2/cli` as package `cli` (mp's), with the two tdns-only dependencies replaced: `MergeViperIncludes` → mpcli's existing single-level include shim in `root.go`, `ApiDetails.Role` → an mp-side `apiservers` reader that also reads `role:` (viper ignores unknown fields, so the pinned `InitApiClients` is unaffected). `RegisterRole`, `GetApiClient`, `NewZoneCmd(role, extras…)`, `NewDebugCmd(role, extras…)` exist in the pinned cli and are all that is needed from tdns. | **Recommended.** Independent of F0; when F0 lands the copy is deleted and the imports repointed — same names, same behaviour, by construction. |
| C. wait for F0 | | The rig is wanted now. No. |

## 4. The work (option B)

1. **Mechanism** (~0.5 day): the two files above, adapted; a
   `TestNoHardcodedRoleRemains` that parses the package the way tdns's
   guard does (parse, not grep: a grep matches prose about the problem).
2. **Factories** (~1–1.5 days, mechanical): every static command var
   that reaches an API becomes `NewXxxCmd(role)`, with
   `var XxxCmd = NewXxxCmd("agent")`-style shims so the canonical
   wiring compiles unchanged; then four tree factories
   `NewAgentTree`, `NewCombinerTree`, `NewSignerTree`, `NewAuditorTree`
   in mp's cli package, built from the same factories
   `cmd/mpcli/shared_cmds.go` calls. The mp zone subcommands stop being
   pushed into tdns's static `AgentZoneCmd` from `init()` and are
   instead passed as `extras` to `NewZoneCmd(role, extras…)` in both
   the canonical wiring and the instance tree. The 29 hardcoded sites
   become `GetApiClientForCmd(cmd, …)` and the four canonical roots are
   tagged in one `init()`. Shape is proven preserved the way tdns did
   it: `--help` text and the command-path set of every converted
   subtree byte-identical before and after.
3. **Wiring** (~0.5 day): `wireInstances()` in `cmd/mpcli/root.go`
   before `ExecuteContext` (a copy of ncli's, ~20 lines);
   `knownInstanceRoles` = the four mp roles; the instance name is the
   command word; a `TestInstanceTreeMatchesCanonical{Agent,Combiner,Signer,Auditor}Tree`
   in `cmd/mpcli` so a command added to one and not the other fails a
   test instead of surprising an operator.
4. **Two small things worth doing at the same time:**
   - honour an environment variable for the CLI config path
     (`TDNS_MPCLI_CONFIG`; `--config` wins), so a rig session is
     `export TDNS_MPCLI_CONFIG=/var/tmp/mp-policy-matrix/tdns-mpcli.yaml`
     once and plain `tdns-mpcli p2-agent …` after;
   - `--json` on `zone mplist`, `zone edits list`, `keystore dnssec
     list`, `gossip state`, `auditor zones`: the rig's assertion layer
     (§7 of the rig design) reads those, and text tables are its
     fragile part.

Total: two to three days, none of it novel — every step is one tdns
already took and documented, on a smaller tree.

## 5. Config shape (identical to tdns-ncli)

```yaml
apiservers:
   # canonical entries, unchanged: name = registered clientKey
   - name:       tdns-mpagent
     baseurl:    https://127.0.0.1:7054/api/v1
     apikey:     …
     authmethod: X-API-Key

   # instances: name = command word = clientKey; role picks the tree
   - name:       p2-agent
     role:       agent
     baseurl:    https://127.0.0.1:7254/api/v1
     apikey:     …
     authmethod: X-API-Key
     command:    /usr/local/libexec/tdns-mpagent
   - name:       p2-combiner
     role:       combiner
     baseurl:    https://127.0.0.1:7255/api/v1
     …
```

Entries without `role:` behave exactly as today, so an existing
`/etc/tdns/tdns-mpcli.yaml` is untouched by the change. The rig's
`setup.sh` writes one such file with eleven entries (`p1-agent` …
`p3-signer`, `aud`), and `lib.sh` calls `tdns-mpcli <instance> …`
directly — the same words a human types, which is the point.

## 6. Delivery: in place, or a parallel `tdns-mpncli`?

tdns ships the behaviour as a **second binary** because tdns-ncli is a
prototype and tdns-cli is depended on by everything (Johan, twice,
2026-09-07). For tdns-mpcli the trade-off is different:

- the additive part (instance trees) only activates on `role:`
  entries, which no existing config has;
- the shared part (29 sites → `GetApiClientForCmd`, vars → factories)
  is a provable no-op for the canonical trees, with the same
  byte-identical-help guard tdns used;
- tdns-mpcli has one operator and a testbed, not a fleet of written
  procedures;
- a third CLI binary (`tdns-cli`, `tdns-ncli`, `tdns-mpcli`,
  `tdns-mpncli`) is a real cost for the humans the rig is meant for.

Recommendation: **in place**, in tdns-mpcli, on its own branch off
`transport-redesign-v1-C`, merged only after the rig has exercised it
for a while. If the prototype status of tdns-ncli is the deciding
principle rather than the risk analysis, the parallel-binary route
costs one extra `cmd/mpncli/` directory with a 50-line `shared_cmds.go`
copy and the same drift test tdns has; everything in §4 is identical.
Johan's call; the plan does not change.

## 7. What the rig does meanwhile

Until this lands, `lib.sh` uses a two-line wrapper,
`mp() { tdns-mpcli --config "$RIG/$1/tdns-mpcli.yaml" "${@:2}"; }`,
with one small config per provider. The instance names in the rig
docs are chosen now (`p1-agent`, …, `aud`) so that nothing in the rig's
prose changes when the wrapper goes away.

---

# Implementation appendix (added 2026-09-10, same day)

Everything below was checked against the pinned tdns cli module
(`v0.0.0-20260611090745`) and the tdns-mp `v2/cli` package on
`transport-redesign-v1-C`, so an implementer does not have to re-derive
it. Branch: cut from `transport-redesign-v1-C`; one commit per step;
every step leaves the canonical trees byte-identical in `--help`.

## A. What the pinned tdns cli provides, and what it gets wrong

Provides, and is used as-is: `RegisterRole`, `GetApiClient(role, …)`,
`GetClientKeyFromParent`, `GetApiDetailsByClientKey`, `InitApiClients`,
`ValidateConfig`, and the role-taking factories `NewPingCmd`,
`NewStopCmd`, `NewDaemonCmd`, `NewDebugCmd(role, extras…)`,
`NewConfigCmd`, `NewZoneCmd(role, extras…)`, `NewKeystoreCmd`,
`NewTruststoreCmd`. The keystore subtree is role-clean: every leaf
goes through `dnssecKeyMgmt(role, …)` / `sig0KeyMgmt(role, …)`, so
`p2-signer keystore dnssec generate|rollover|list` will target p2.

Gets wrong (pre-existing, unchanged by this work, fixed upstream on
2026-09-07 and therefore fixed here by F0):

- Inside `newKeystoreDnssecCmd` the leaves `policy`, `ds-push`,
  `query-parent` and `auto-rollover` (and its `validate`) hardcode
  `GetApiClient("auth")`. On the fleet today
  `tdns-mpcli signer keystore dnssec policy …` dies with "No API client
  found for tdns-auth". This is cosmetic for mp: those leaves call
  `/rollover/*` and `/config/paths`, tdns-auth's KSK-rollover
  automation, which the mp signer does not serve at all (its routes:
  `/keystore`, `/signer`, `/zone/dsync`, `/delegation`, …), so a
  correct role would only change the error message. The leaves the
  rig needs — `generate`, `rollover`, `list` — are role-clean and hit
  `/keystore`, which the mp signer implements. Step 4 prunes the four
  from the signer trees (`RemoveCommand`) so `--help` stops
  advertising them; one line to undo if the signer ever serves them.
- `cli.AuthCmd` and `cli.ReportCmd` are attached under `SignerCmd`.
  `signer auth …` already fails the same way (verified on the fleet:
  "No API client found for tdns-auth"). Both are static vars, so they
  cannot hang off a second tree. **Deliberately absent on instance
  trees**, listed as such in the drift test.
- `cli.AgentZoneCmd` is a static var whose tdns `init()` attaches
  tdns's own `list reload write update readfake dsync`, and mp's
  `init()` attaches mp's own `mplist bump reload write update readfake
  dsync addrr delrr edits` to the same parent. The canonical
  `agent zone` tree therefore carries two `reload`, two `write`, two
  `update`, two `readfake` and two `dsync` today, and which one cobra
  runs depends on registration order. Step 3 fixes this as a side
  effect.

## B. Inventory (tdns-mp `v2/cli`)

Static `var xxxCmd = &cobra.Command{}` per file, and the parent each
file attaches to. 117 in total; the ones that never reach an API
(`keys generate`, `jwt`) stay as they are.

| File | vars | attaches to | becomes |
|---|---|---|---|
| `agent_cmds.go` | 12 | `AgentCmd`, local/zonedata/peer subtrees | `NewAgentCmd(role)` root + `newAgentLocalCmd(role)`, `newAgentPeerCmd(role)` |
| `agent_zone_cmds.go` | 15 | tdns `AgentZoneCmd` | `NewAgentZoneCmd(role)` (see step 3) |
| `agent_edits_cmds.go` | 2 | tdns `AgentZoneCmd` | leaf of `NewAgentZoneCmd` |
| `agent_debug_cmds.go` | 13 | `DebugAgentCmd` | `NewDebugAgentCmd(role)`, passed as extras to tdns `NewDebugCmd(role, …)` |
| `agent_imr_cmds.go` | 1 | `AgentCmd` | leaf of `NewAgentCmd` |
| `hsync_cmds.go` | 11 | `AgentCmd` / `hsyncCmd` | `newHsyncCmd(role)` |
| `distrib_cmds.go` | 14 | `Agent/Combiner/AuditorDistribCmd` | `NewDistribCmd(role)` — one factory, the three vars were already role-shaped copies |
| `transaction_cmds.go` | 8 | `Agent/CombinerTransactionCmd` | `NewTransactionCmd(role)` |
| `combiner_cmds.go` | 4 | `CombinerCmd` | `NewCombinerCmd(role)` root |
| `combiner_edits_cmds.go` | 12 | `combinerZoneCmd`/`…EditsCmd` | `newCombinerZoneCmd(role)` |
| `combiner_config_cmds.go` | 2 | `combinerConfigCmd` | `newCombinerConfigCmd(role)` |
| `combiner_debug_cmds.go` | 1 | `CombinerCmd` | leaf |
| `combiner_peer_cmds.go` | 3 | `combinerPeerCmd` | `newCombinerPeerCmd(role)` |
| `signer_cmds.go` | 2 | `SignerCmd` | `NewSignerCmd(role)` root; `mplist` leaf as extra to `NewZoneCmd` |
| `auditor_cmds.go` | 7 | `AuditorCmd`, eventlog | `NewAuditorCmd(role)` root + `newAuditorEventlogCmd(role)` |
| `auditor_web_cmds.go` | 6 | `auditorWebCmd`, `…UserCmd` | `newAuditorWebCmd(role)` |
| `router_cmds.go` | 18 | (its own subtree) | `newRouterCmd(role)` |

Already factories, reused unchanged: `NewGossipCmd(role)`,
`NewPeerCmd(role)`, `NewKeysCmd(role)`, `NewAuditorPeerListCmd()`,
`NewAuditorPeerZonesCmd()` (the last two take no role: give them one).

The 29 hardcoded sites, all of the form `api, err := GetApiClient("<role>", true)`:

```
agent_edits_cmds.go:274  agent_cmds.go:43,291  agent_debug_cmds.go:583,780
agent_zone_cmds.go:69,98,164,213,245,278,308,380,454
auditor_cmds.go:136
combiner_edits_cmds.go:36,67,367,462,488  combiner_debug_cmds.go:129
combiner_config_cmds.go:38  combiner_cmds.go:66
hsync_cmds.go:45  distrib_cmds.go:372,818  signer_cmds.go:26
transaction_cmds.go:167,230
```

Twenty-two sit in `Run` closures (they have `cmd`); seven are in
helpers (`agent_cmds.go:291`, `agent_debug_cmds.go:780`,
`auditor_cmds.go:136`, `combiner_edits_cmds.go:367`,
`combiner_debug_cmds.go:129`, `combiner_cmds.go:66`,
`distrib_cmds.go:372,818`, `hsync_cmds.go:45`, `transaction_cmds.go:167,230`)
whose only callers are `Run` closures: thread `cmd *cobra.Command` in,
as tdns did for `runWhenOnline`.

`jose_keys_cmds.go:62,69` use `GetClientKeyFromParent(role)` with the
factory's role — correct already.

## C. Steps

**Step 1 — mechanism (`v2/cli/role_target.go`, `v2/cli/instances.go`).**
Copy from tdns `v2/cli` at `d9071e65`. Changes:

- package `cli` (tdns-mp's), imports `tdnscli` for `RegisterRole`,
  `GetApiClient`, `ApiDetails`.
- `GetApiClientForCmd` calls `tdnscli.GetApiClient(role, …)`.
- The `init()` that tags canonical trees moves to step 4 (the mp roots
  are not built until then). Do not tag tdns's `AuthCmd` etc.
- `instances.go`: `EarlyApiServers` unmarshals into a local
  `type instanceEntry struct { Name, Role string }` (yaml tags `name`,
  `role`) instead of `ApiDetails`, because the pinned `ApiDetails` has
  no `Role`; the pinned `viper.Unmarshal` into `CliConf` ignores the
  unknown `role:` key, so the full load in `PersistentPreRun` is
  unaffected. Replace `tdns.MergeViperIncludes` with the single-level
  include loop already in `cmd/mpcli/root.go` (move it into the
  package as `mergeIncludes(v, cfgFile)` and have `root.go` call it
  too, so both loads see the same includes). Replace
  `tdns.DefaultCliCfgFile` with `defaultMpcliCfgFile`
  (`/etc/tdns/tdns-mpcli.yaml`), exported from the package.
- `knownInstanceRoles` = `agent`, `combiner`, `signer`, `auditor` →
  the four tree factories of step 4.
- `TestNoHardcodedRoleRemains`: parse `v2/cli` with `go/parser`, fail
  on any `GetApiClient` call whose first argument is a string literal.
  Committed failing-on-purpose? No — commit it in step 5 when it
  passes; until then it is the checklist.

**Step 2 — factories with shims.** For each row of table B, convert
`var fooCmd = &cobra.Command{…}` to `func newFooCmd(role string)
*cobra.Command { c := &cobra.Command{…}; …; return c }` and keep
`var fooCmd = newFooCmd("<canonical role>")` where anything else in
the package references the var. `init()` bodies that did
`parent.AddCommand(child)` move into the parent's factory. Flag
bindings to package vars stay (bound twice, harmless — only one
command runs per invocation; tdns verified this). Sub-steps, each a
commit: distrib+transaction (pure copies today), combiner subtree,
auditor subtree, hsync+router, agent subtree.

**Step 3 — `NewAgentZoneCmd(role)`.** mp-owned `zone` subtree with
`--force`/`-F` persistent flag (mp's `addrr`/`delrr` read it via
`cmd.Flags().GetBool("force")`; today it comes from tdns's parent),
children `mplist bump list reload write update/create readfake
dsync/{status,bootstrap-sig0-key,roll-sig0-key,publish,unpublish}
addrr delrr edits`. `list` is the one tdns-only leaf: copy its ten
lines. Then in `cmd/mpcli/shared_cmds.go` replace
`AgentCmd.AddCommand(cli.AgentZoneCmd)` with
`AgentCmd.AddCommand(mpcli.NewAgentZoneCmd("agent"))` and delete mp's
`init()` pushes into `tdnscli.AgentZoneCmd`. Canonical `agent zone
--help` loses the duplicate names and gains nothing else; assert that
in the shape test by comparing the de-duplicated before-set with the
after-set.

**Step 4 — tree factories and tagging.** `v2/cli/trees.go`:
`NewAgentTree(use, role)`, `NewCombinerTree`, `NewSignerTree`,
`NewAuditorTree`, each `TagRole`d, each an exact transcription of the
role's block in `cmd/mpcli/shared_cmds.go` (lines 24–36, 41–49,
52–66, 73–87 at `74f2f09`) minus the static tdns vars (`AuthCmd`,
`ReportCmd`, `RootKeysCmd`, `JwtCmd` under signer). Keystore and
truststore last, as in `NewAuthTree`, because their help text is built
at construction from the algorithms registered in `init()`. In
`NewSignerTree` (and the canonical signer wiring, same code path) take
the `dnssec` child of `NewKeystoreCmd(role)` and `RemoveCommand` its
`policy`, `ds-push`, `query-parent` and `auto-rollover` leaves — see A;
they target endpoints the mp signer does not have. Then
`shared_cmds.go` itself becomes four calls: `rootCmd.AddCommand(
mpcli.NewAgentTree("agent","agent"), …)`, which makes the canonical
tree and the instance tree the same code path and deletes the drift
risk instead of testing for it. Tag the four canonical roots in a
package `init()` (`TagRole(AgentCmd,"agent")` …) only if step 2's
shims keep those vars; otherwise the factories tag.

**Step 5 — the 29 sites → `GetApiClientForCmd(cmd, true)`.** Commit
the parse-based guard with it.

**Step 6 — wiring (`cmd/mpcli/root.go`).** `wireInstances()` verbatim
from `cmdv2/ncli/root.go`: `InitDefaultHelpCmd`,
`InitDefaultCompletionCmd`, `ConfigPathFromArgs(os.Args[1:])`,
`WireInstanceTrees(rootCmd, EarlyApiServers(path))`, warnings to
stderr prefixed `tdns-mpcli:`. Called from `ExecuteContext` before
`rootCmd.ExecuteContext`. Reserved words an instance may not take:
`agent`, `combiner`, `signer`, `auditor`, `version`, `configure`,
`keys`, `help`, `completion`, plus any earlier instance name — all
refused with the existing messages. `--config` handling: also honour
`TDNS_MPCLI_CONFIG` in both `ConfigPathFromArgs` and `initConfig`
(flag wins over env wins over default).

**Step 7 — tests (`cmd/mpcli`).**
`TestInstanceTreeMatchesCanonical{Agent,Combiner,Signer,Auditor}Tree`
(path-set equality, with the signer's `auth`/`report`/`keys`/`jwt`
as the deliberately-absent list);
`TestCanonicalHelpUnchanged` (golden `--help` for every subtree,
recorded before step 2, de-duplicated once for step 3);
`TestInstanceWiringFromConfig` (a temp yaml with one `role:` entry
per role → four instance words exist, a colliding name is refused
with the right message, a nameless entry is skipped).

**Step 8 — docs.** `guide/app-mpcli.md`: the `role:` field, the
instance words, the env var, the known gaps from A. Sample
`cmd/mpcli/tdns-mpcli.sample.yaml`: one commented instance entry.

## D. Acceptance

- `tdns-mpcli agent|combiner|signer|auditor --help` output identical
  before and after, except the de-duplication of `agent zone`.
- A config with `p1-agent … p3-signer, aud` entries gives
  `tdns-mpcli p2-agent zone mplist` and friends; `tdns-mpcli p2-agent
  ping` reports the p2 daemon's identity; `GetApiClientForCmd` on
  every leaf of every instance tree resolves to that instance's
  clientKey (test walks the tree and calls `RoleForCmd`).
- `go vet`, package tests, the guard test, the drift tests all green.
- Exercised on the rig (phase 0) before it is merged.

## E. When F0 lands

Delete `v2/cli/role_target.go` and `v2/cli/instances.go`, import the
tdns ones, add `Role` to nothing (tdns's `ApiDetails` has it), drop the
local `instanceEntry`. The four tree factories and all conversions
stay; they are the same code tdns would have wanted.

---

# Implemented (2026-09-11)

Branch `mpcli-multi-instance` (cut from `transport-redesign-v1-C` tip
`74f2f09`), four signed commits:

| Commit | What |
|---|---|
| `b702097` | the command tree as a golden file (`cmd/mpcli/tree_test.go`, `testdata/tree-golden.txt`), recorded BEFORE the refactor, duplicates rendered with `#2` |
| `5d00929` | the work: `v2/cli/role_target.go` + `instances.go` (copies of tdns `d9071e65`, adapted), 117 vars → factories, `trees.go` with the four tree factories, `cmd/mpcli/shared_cmds.go` reduced to four calls, `wireInstances()` in `root.go`, `TDNS_MPCLI_CONFIG`, golden regenerated |
| `7c26629` | the tests of appendix step 7, under the names in the table below |
| `0e6efc4` | `guide/app-mpcli.md` section, `tdns-mpcli.sample.yaml` entry |

Deviations from the appendix, all small:

- Helpers that need the daemon type take a `kind` parameter and read the
  target from `cmd` (`GetApiClientForCmd`/`RoleForCmd`); factories take
  `kind`, tree factories take `(use, role)`. `NewAgentZoneCmd(role, kind)`
  takes both because it lifts tdns's `zone list` leaf out of
  `NewZoneCmd(role)` so its `-f/-N/-P` flags (bound to tdns-private
  variables) survive; that replaced the planned ten-line copy.
- Two more pre-existing duplications surfaced and were folded in the same
  way as `agent zone`: `agent debug` (mp's leaves now sit beside tdns's
  under one `debug`; tdns's `lav`, `rrset`, `show-ta` … become reachable)
  and `combiner config` (tdns's `reload`/`reload-zones` become reachable;
  `status` stays the combiner's own).
- The shape guard is one golden of the whole tree rather than per-subtree
  `--help` goldens; `TestCanonicalHelpUnchanged` in the plan is
  `TestCommandTreeGolden`. Every flag of every command is in it.
- The pinned `ApiDetails` field is `config_file`, not `config-file`.
- The mechanism files were not tagged with an `init()`: the tree
  factories tag their roots, and nothing static is left to tag.

Tests: `TestCommandTreeGolden`, `TestInstanceTreeMatchesCanonicalTree`,
`TestInstanceWiringFromConfig`, `TestConfigPathPrecedence` (cmd/mpcli);
`TestNoHardcodedRoleRemains`, `TestRoleForCmdWalksUp`,
`TestEveryTreeLeafResolvesItsInstance` (v2/cli). Smoke-tested with a
config of fake ports: `p2-signer keystore dnssec list` dials the p2
port, `agent ping` the built-in one, the env var replaces `--config`, a
colliding name is refused on stderr, `keys generate --help` works with
no config at all. Not merged; to be exercised by the rig first (§6).
