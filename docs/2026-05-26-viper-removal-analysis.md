# Viper removal: analysis (tdns-mp/v2)

Date: 2026-05-26
Status: ANALYSIS — no implementation work scheduled.
Scope: tdns-mp/v2 (this repo). The corresponding tdns analysis lives at
[tdns/docs/2026-05-26-viper-removal-analysis.md](https://github.com/johanix/tdns/blob/main/docs/2026-05-26-viper-removal-analysis.md).

## Critical observation up front

**Removing viper from tdns-mp alone does not change the dependency
footprint.** tdns/v2 still imports viper extensively (99 sites across
39 files). As long as tdns-mp depends on tdns/v2, the binary's
go.sum still carries every viper transitive dependency. Vulnerability
scanners, SBOMs, and supply-chain audits see the same noise either way.

The actual lever for removing viper from the dependency graph is
removing viper from **tdns**. See the corresponding analysis in
tdns/docs/.

This document exists because:

1. tdns-mp's viper usage is small and well-bounded; if we *do* commit
   to the full removal, the tdns-mp side is the easier half and can be
   done independently.
2. Future tdns-mp-only engines should not add new viper reads.
3. If we choose incremental opportunistic removal (Option C in the
   tdns doc), tdns-mp can clean its half ahead of tdns without harm.

## Motivation

(Same as tdns side — supply-chain footprint, vulnerability scan
noise, SBOM cleanliness. See the tdns doc's "Motivation" section
for the dependency-tree numbers.)

## Current state in tdns-mp/v2

### Numbers (audit 2026-05-26)

- **20 viper-Get sites** across 7 files in tdns-mp/v2.
- 14 distinct literal keys, plus 2 sites with computed keys
  (`parseKeygenAlgorithm`, `configureInterval`).

### Files touching viper

| File | Sites |
|---|---|
| `auditor_web.go`   | 8 |
| `start_auditor.go` | 4 |
| `agent_setup.go`   | 1 (computed: keygen algorithm) |
| `agent_utils.go`   | 2 |
| `mp_resigner.go`   | 2 |
| `start_agent.go`   | 1 |
| `hsync_hello.go`   | 1 (computed: configureInterval) |

### Key inventory

Keys read directly from tdns-mp code:

```
agent.remote.locateinterval         (PARTIALLY MAPPED in tdns: field exists, no yaml tag)
agent.update.keygen.algorithm       (FULLY MISSING)
audit.detector_interval             (FULLY MISSING — no AuditConf in tdns/v2)
audit.event_log.prune_interval      (FULLY MISSING)
audit.event_log.retention           (FULLY MISSING)
audit.silence_threshold             (FULLY MISSING)
audit.web.addresses                 (FULLY MISSING)
audit.web.auth.idle_timeout         (FULLY MISSING)
audit.web.auth.mode                 (FULLY MISSING)
audit.web.auth.users_file           (FULLY MISSING)
audit.web.cert_file                 (FULLY MISSING)
audit.web.enabled                   (FULLY MISSING)
audit.web.key_file                  (FULLY MISSING)
delegationsync.leader-election-ttl  (FULLY MISSING — no DelegationSyncConf in tdns/v2)
multi-provider.syncengine.intervals.beatinterval        (PARTIALLY MAPPED)
multi-provider.syncengine.intervals.discoveryretry      (PARTIALLY MAPPED)
multi-provider.syncengine.intervals.hello_fast_attempts (PARTIALLY MAPPED)
multi-provider.syncengine.intervals.hello_fast_interval (PARTIALLY MAPPED)
multi-provider.syncengine.intervals.helloretry          (PARTIALLY MAPPED)
multi-provider.syncengine.intervals.reconcile           (PARTIALLY MAPPED)
resignerengine.interval             (FULLY MISSING)
resolver.address                    (FULLY MISSING)
service.resign                      (FULLY MISSING)
```

Most of tdns-mp's viper usage is for the audit subsystem, which has
**no struct representation anywhere** today. The auditor was added
as a tdns-mp engine and reaches config exclusively through viper.

## Where the work would have to happen

The keys split unfortunately across both repos:

- **AuditConf** — used only by tdns-mp's auditor. Belongs in
  tdns-mp/v2. New struct on `tdnsmp.Config` (or extension to
  `InternalMpConf`). Self-contained — tdns-mp can add this without
  touching tdns.
- **DelegationSyncConf** — used by both repos. Most call sites are
  in tdns/v2/. Has to live in tdns/v2/config.go.
- **MultiProvider.Syncengine.Intervals.*** — field exists in
  MultiProviderConf, just needs yaml tags. **The MultiProviderConf
  struct currently lives in tdns/v2 but is planned to migrate to
  tdns-mp/v2** (see the in-progress shadow parser in
  `shadow_mp_config.go`). Whether we add yaml tags before or after
  that migration matters for ordering.
- **agent.remote.*** — same MultiProviderConf situation.
- **agent.update.keygen.algorithm, resolver.address, service.resign,
  resignerengine.interval** — each is one site in tdns-mp but the
  config key conceptually belongs in tdns/v2's struct hierarchy
  (these aren't MP-specific concepts).

So even a tdns-mp-only viper removal would require either:

1. Adding yaml tags to tdns-side structs (5 minutes per tag, but
   touches the tdns repo).
2. Pulling some keys into a tdns-mp-only struct (e.g. an
   `auditor.local.*` namespace just for tdns-mp).
3. Accepting that some tdns-mp viper reads stay until tdns's removal
   happens.

## Effort estimate (tdns-mp side only)

If tdns ever gets its full viper removal, the tdns-mp companion work is:

- **1-2 hours**: design `AuditConf` struct hierarchy. ~12 fields.
- **1 hour**: add yaml tags to MultiProvider.Syncengine.Intervals
  fields (this is also called out in the tdns analysis as
  PARTIALLY MAPPED).
- **1-2 hours**: replace ~20 viper call sites with struct access.
  Mechanical.
- **1-2 hours**: testing each mp* daemon with real configs.
- **1 hour**: surprises.

**Total: 5-8 hours**, depending on how much can be batched with the
tdns side.

## Strategic recommendation

Mirror what the tdns analysis recommends: **incremental opportunistic
removal**. When a tdns-mp file is touched for other reasons, convert
its viper reads to struct reads at the same time.

Two specific things tdns-mp can do unilaterally without waiting on tdns:

1. **Add `AuditConf` to tdns-mp** as a proper sub-struct on
   `tdnsmp.Config`. Switch the 12 audit viper reads to struct reads.
   This is a self-contained tdns-mp PR, no tdns changes needed.
   Estimated ~3-4 hours.
2. **Do not add new viper reads.** Code that grows in tdns-mp should
   reach config via struct fields. If a needed field doesn't exist,
   add it to `tdnsmp.Config` (or for tdns-owned fields, propose the
   struct addition upstream).

The remaining 8 tdns-mp viper reads outside the audit subsystem can
wait for the eventual tdns-side removal.

## Out of scope

Same as the tdns side: this is analysis only, no implementation work
is scheduled. Removing viper is a substantial multi-session effort
that should be triggered by a specific concern (CVE in a viper
transitive dep, scanner noise threshold, external consumer complaint)
rather than tackled in a regular maintenance window.
