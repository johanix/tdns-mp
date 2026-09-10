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
