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

### Bite 2: combiner-only sites
Convert all 100% combiner-only call sites:

    combiner_chunk.go
    combiner_crypto.go
    combiner_msg_handler.go
    combiner_peer.go
    combiner_utils.go
    start_combiner.go

Self-contained. Runtime testable on the operator's mpcombiner alone.

### Bite 3: signer-only sites
Same shape:

    signer_keydb.go
    signer_msg_handler.go
    signer_peer.go
    signer_transport.go

### Bite 4: agent-only sites
    agent_setup.go
    agent_structs.go
    agent_utils.go
    apihandler_agent.go
    apihandler_agent_distrib.go
    apihandler_agent_hsync.go
    apihandler_peer.go
    start_agent.go

### Bite 5: auditor-only sites
    start_auditor.go
    apihandler_imr.go (auditor-relevant parts)

### Bite 6: shared / multi-role sites
Whatever remains:

    apihandler_combiner.go
    apihandler_transaction.go
    hsync_utils.go
    hsyncengine.go
    key_state_worker.go
    keys_cmd.go
    main_init.go
    mp_extension.go
    syncheddataengine.go
    config_validate.go
    cli/agent_debug_cmds.go
    transport_harness_test.go

### Bite 7: `*tdns.Config` call sites
The ~12 hardest sites. For each, decide (a)/(b)/(c) from above
and apply. Some may be in tdns-mp helper functions that should
take `*tdnsmp.Config` to begin with.

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
