# MultiProvider config cutover plan

Date: 2026-05-26
Status: PLAN — implementation pending operator's verification window.
Predecessor: shadow MP-config parser landed in tdns-mp PR #29
(commit 363858d on main).

## Where we are

The `MultiProviderConf` struct, its YAML parsing, FQDN normalization,
and option-string-to-enum decoding all currently live in tdns/v2.
They were left there from the original monolith and are the last
piece of multi-provider-specific state in tdns.

Since PR #29 merged, tdns-mp also runs the same parse independently
(via the `PostParseConfigHook` added in tdns PR #236) and stashes the
result on `conf.InternalMp.MpConfig`. Every MP daemon startup logs
the comparison:

    INFO shadow MP parser: identical to tdns-side parse

(All three MP daemons currently report identical on operator's
production configs.)

The shadow has been observed faithful. We can now cut over runtime
accessors to read from `conf.InternalMp.MpConfig` instead of
`conf.Config.MultiProvider`. Once accessors are cut over and proven
stable, the struct can be deleted from tdns entirely.

## Scope

In tdns-mp/v2: **~156 accessor sites across 34 files**, in two access
shapes:

> **Validation update (2026-05-27):** Site counts re-measured after
> Bite 1 landed. Actual: **137 sites across 19 files** (counting only
> `conf.*MultiProvider` reads — not type declarations, not struct
> literals). The plan's original ~156/34 was higher because it
> double-counted some files and included files with zero relevant
> sites. See "Per-bite site counts" below. Direction is unchanged;
> the bite boundaries still hold.


- `conf.Config.MultiProvider.X` when `conf` is `*tdnsmp.Config`
- `conf.MultiProvider.X` when `conf` is `*tdns.Config`

Distribution of the 20 most common access shapes:

```
32  conf.Config.MultiProvider.Identity
21  conf.Config.MultiProvider                       (whole-struct ref)
12  conf.MultiProvider                              (whole-struct ref, on *tdns.Config)
 8  conf.Config.MultiProvider.Signer.Address
 8  conf.Config.MultiProvider.Combiner.Address
 7  conf.MultiProvider.Agents
 6  conf.MultiProvider.LongTermJosePrivKey
 6  conf.Config.MultiProvider.Api.Port
 5  conf.Config.MultiProvider.Signer.LongTermJosePubKey
 5  conf.Config.MultiProvider.Dns.Port
 5  conf.Config.MultiProvider.Combiner.LongTermJosePubKey
 4  conf.MultiProvider.Role
 4  conf.MultiProvider.Identity
 4  conf.Config.MultiProvider.Signer.Identity
 4  conf.Config.MultiProvider.Combiner.Identity
 3  conf.MultiProvider.Local.Nameservers
 3  conf.Config.MultiProvider.Local.Nameservers
 3  conf.Config.MultiProvider.Dns.Addresses.Publish
 3  conf.Config.MultiProvider.Api.Addresses.Publish
 2  conf.MultiProvider.SupportedMechanisms
```

## The complication: two `conf` types

Most call sites (~144) are inside methods receiving `*tdnsmp.Config`
or local variables of that type. For those, the conversion is mechanical:

    conf.Config.MultiProvider.X  →  conf.InternalMp.MpConfig.X

The remaining ~12 call sites read `conf.MultiProvider.X` from a
`*tdns.Config`. `*tdns.Config` has no `InternalMp` and (post-cutover)
won't have a `MultiProvider` field either. Those sites need one of:

- **(a) Change the function signature** to take `*tdnsmp.Config` so it
  can reach `InternalMp.MpConfig`.
- **(b) Pass `*tdnsmp.MultiProviderConf` as a separate parameter** to
  the function.
- **(c) Use a package-level accessor** (e.g. `tdnsmp.WiredMpConfig()`)
  that returns the current `*MultiProviderConf` — there's already a
  precedent for this with `wiredMultiProvider` in `mp_extension.go`.

(c) is the lowest-friction option for tdns-side code paths that
shouldn't take a tdns-mp type. (a) is cleaner when the function is
already tdns-mp-internal but accidentally took `*tdns.Config`. (b) is
for one-off cases where neither (a) nor (c) fits naturally.

## Cutover strategy: bite-by-bite, file at a time

A single 156-site PR would be:
- Hard to review (mechanical sed across 34 files).
- Hard to bisect if a regression surfaces.
- All-or-nothing in terms of rollback.

Instead, do it in small thematic bites, each in its own PR:

### Bite 1: prep
Add a public accessor on `*tdnsmp.Config` for legibility:

    func (conf *Config) MpConfig() *tdns.MultiProviderConf {
        return conf.InternalMp.MpConfig
    }

Plus a package-level accessor for the `*tdns.Config` callers:

    func WiredMpConfig() *tdns.MultiProviderConf {
        return wiredMpConfig
    }

(The existing `wiredMultiProvider` already follows this pattern and
should be renamed to `wiredMpConfig` to align.)

No call-site changes yet. Just adds the accessors and a sanity
check that they return the expected value at boot.

### Bite 2: combiner-only sites — 31 sites, 6 files
Convert all 100% combiner-only call sites:

    combiner_chunk.go        ( 1)
    combiner_crypto.go       ( 3)
    combiner_msg_handler.go  ( 3)
    combiner_peer.go         (18)
    combiner_utils.go        ( 5)
    start_combiner.go        ( 1)

Self-contained. Runtime testable on the operator's mpcombiner alone.

### Bite 3: signer-only sites — 22 sites, 3 files
Same shape:

    signer_msg_handler.go    ( 3)
    signer_peer.go           (18)
    signer_transport.go      ( 1)

(signer_keydb.go was in the original plan but has zero MP-config
sites; dropped.)

### Bite 4: agent-only sites — 68 sites, 7 files
**Note:** agent_setup.go alone is 42 sites — the largest single file
in the cutover. Consider splitting Bite 4 into 4a (agent_setup.go)
and 4b (the rest) if review burden warrants.

    agent_setup.go             (42)
    agent_utils.go             ( 5)
    apihandler_agent.go        ( 9)
    apihandler_agent_distrib.go( 4)
    apihandler_agent_hsync.go  ( 1)
    apihandler_peer.go         ( 1)
    start_agent.go             ( 6)

(agent_structs.go was in the original plan but has zero MP-config
sites; dropped.)

### Bite 5: auditor-only sites — 2 sites, 2 files

    start_auditor.go         ( 1)
    apihandler_imr.go        ( 1)

### Bite 6: shared / multi-role sites — 41 sites, 9 files
Whatever remains:

    apihandler_combiner.go    ( 5)
    apihandler_transaction.go ( 1)
    config_validate.go        (18)
    hsyncengine.go            ( 1)
    key_state_worker.go       ( 1)
    keys_cmd.go               ( 2)
    main_init.go              ( 5)
    syncheddataengine.go      ( 3)
    config.go                 ( 3 — including the new MpConfig() method's
                                  one internal read, which is fine to keep)

Files dropped from the original plan list (zero MP-config sites):
hsync_utils.go, cli/agent_debug_cmds.go, transport_harness_test.go
(the test has one `&tdns.MultiProviderConf{...}` literal, not a
config read — leave it alone; it's exercising the type, which stays
in tdns until Bite 9).

mp_extension.go was already touched in Bite 1 and contains only
type declarations and the `wiredMpConfig` assignment — no further
work needed here.

**Out of scope for Bite 6:** `cli/configure/parse.go` has 8 lines
matching `y.MultiProvider.X`, but `y` is a local YAML-unmarshal
struct (`mpagentYAML`, `mpsignerYAML`, etc.), not a
`*tdns.MultiProviderConf`. Different code path, not part of the
cutover.

`shadow_mp_config.go` reads `conf.Config.MultiProvider` to do the
shadow comparison — that's exactly what it should do until Bite 8
removes the comparison entirely. Leave it.

**Per-bite site counts (validated 2026-05-27):**

| Bite | Scope          | Files | Sites |
|------|----------------|-------|-------|
| 2    | combiner-only  |   6   |  31   |
| 3    | signer-only    |   3   |  22   |
| 4    | agent-only     |   7   |  68   |
| 5    | auditor-only   |   2   |   2   |
| 6    | shared         |   9   |  41   |
| **Total** |           | **27** | **164** |

(Total exceeds the bite breakdown by ~27 because some files contain
both `conf.Config.MultiProvider.X` shape sites and bare
`conf.MultiProvider.X` shape sites, counted separately. The bare-
shape sites all get handled within their owning bite where the
function signature change is local — Bite 7 only catches the
genuine `*tdns.Config` call sites that can't be locally converted.)

### Bite 7: `*tdns.Config` call sites (revised 2026-05-27)
After the bite-6 review, the deferred-to-Bite-7 backlog turned out
to split into two camps:

**(7a) Convert in Bite 7 — change signatures (option (a)/(b)):**
Three crypto-init helpers, all called from `tdnsmp.MainInit` with
`conf.Config`. Change signature `*tdns.Config` → `*tdnsmp.Config`;
body reads `conf.MpConfig()`. All callers are in MainInit *after*
the shadow parser has run, so `conf.InternalMp.MpConfig` is
populated.

    combiner_crypto.go  InitCombinerCrypto  ( 3 sites)
    signer_transport.go initSignerCrypto    ( 1 site)
    main_init.go        initAgentCrypto     ( 1 site, but uses a
                                              local `mp` so 1 edit)

**(7b) Defer to Bite 9 — see review notes below:**
- `config_validate.go` (18 sites). Validators are wired via
  `tdns.PostValidateConfigHook`, which fires *during*
  `tdns.ValidateConfig`, which runs *before* the
  `PostParseConfigHook` that populates `conf.InternalMp.MpConfig`.
  Switching them to `conf.MpConfig()` would read nil at validation
  time. They correctly validate the tdns-side parse today; when
  Bite 9 moves `MultiProviderConf` *into* tdns-mp, the validators
  move with it and will validate the (then-only) tdns-mp struct.
  No-op until then.
- `keys_cmd.go` `getKeysPrivKeyPath` (2 sites). `LoadConfigForKeys`
  does a plain `yaml.Unmarshal` into a bare `tdns.Config`; it does
  NOT call `ParseConfig`, so the shadow parser never runs.
  Switching to `conf.MpConfig()` would read nil. When Bite 9 moves
  the struct, `LoadConfigForKeys` needs a focused YAML decoder
  targeting `*tdnsmp.MultiProviderConf`, and `getKeysPrivKeyPath`
  takes `*tdnsmp.Config` then.
- `main_init.go` line 82 `wiredMpConfig = conf.MultiProvider`. The
  literal bridge between the two structs. Goes away in Bite 9 when
  there is no tdns-side parse to copy from.

**Net Bite 7 scope after review: 5 sites in 3 files.**
Each is a signature change plus a body swap to `conf.MpConfig()`,
plus updating the 3 callers in MainInit to pass `conf` instead of
`conf.Config`.

### Bite 8: delete the shadow comparison
Once all accessors are cut over, the comparison in
`EmitShadowMpComparison` is no longer useful (the shadow IS the
runtime value now). Keep the parse, drop the compare. Or replace
the compare-against-tdns with a compare-against-nothing-just-log.

### Bite 9: delete from tdns
At this point tdns-mp doesn't read `conf.Config.MultiProvider`
anywhere. tdns can delete:

- `MultiProviderConf` struct + sub-types (PeerConf,
  LocalAgentApiConf, LocalAgentDnsConf, ProviderZoneConf,
  CombinerOption, SignerOption, AgentOption)
- The `MultiProvider` field on `tdns.Config`
- `parseMultiProviderOptions()` from `parseoptions.go`
- The MP-related blocks in `parseconfig.go` (role validation,
  primary-zone identity check, FQDN normalization)
- The `LocalIdentity()` accessor on `tdns.Config`
- The `MultiProviderConf` reference in `AgentMgmtResponse`
  (or refactor that struct)

That last bite is a tdns-side PR. The struct definition moves
*into* tdns-mp/v2 as its own file at the same time.

## Verification between bites

After each bite:
1. Build all five mp* binaries.
2. Run the operator's test deployment.
3. Confirm log line still says "shadow MP parser: identical to
   tdns-side parse" — verifies the shadow continues to match the
   tdns-parsed reference even though some/all accessors now read the
   shadow.
4. Functional smoke test of the daemon role being converted.

The shadow comparison is the safety net: as long as both sides parse
the same struct, swapping which one the runtime reads is harmless.

## Estimated effort

- Bites 1, 7, 8, 9: design work, ~1 hour each.
- Bites 2–6: mostly mechanical sed + verify, ~30-60 min each.

Total: **~6-8 hours**, spread across as many sessions as feels
comfortable. Each bite is independently mergeable and reversible.

## Out of scope

- The `OptMultiProvider` zone option and the ~13 tdns runtime
  branches that test it. That's a separate migration (the analysis is
  in [the earlier conversation](#) — search "OptMultiProvider should
  move from tdns to tdns-mp's range" in the project notes).
- `MultiProviderConf` FQDN normalization currently happens in tdns;
  the shadow already does its own copy. Bite 9 removes tdns's copy.
