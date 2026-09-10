# Drift in the underlying `tdns` repo (and the coming compile break)

**Date:** 2026-07-21
**Status:** tracking doc — tdns-mp does **not** currently build against tdns `main`.
**Related prior art:** [`2026-04-11-mp-dependencies-on-tdns.md`](2026-04-11-mp-dependencies-on-tdns.md),
[`2026-04-14-legacy-dependency-analysis.md`](2026-04-14-legacy-dependency-analysis.md).

## TL;DR

tdns-mp pins `github.com/johanix/tdns/v2` (and `/cache`, `/cli`, `/core`,
`/edns0`) at **`v2.0.0-20260611090745-44755a2166f9`** — the merge of tdns
**PR #255, dated 2026-06-11**. As of today tdns `main` is **468 commits ahead**
of that pin. The next time we bump the tdns pin, tdns-mp **will not compile**,
and it is **not a single fix — it is ~10 independent API drifts** plus a fork
(`miekg/dns`) version bump.

This is not hypothetical: the list below comes from actually building
`tdns-mp/v2` against a local checkout of tdns `main` (throwaway `replace`
directives, reverted). Treat a tdns pin bump as a **planned, coordinated task
with a compile-fix pass**, never a casual dependency refresh.

## The current pin

```
# tdns-mp/v2/go.mod
github.com/johanix/tdns/v2       v2.0.0-20260611090745-44755a2166f9   # tdns PR #255, 2026-06-11
github.com/johanix/tdns/v2/cache v0.0.0-20260611090745-44755a2166f9
github.com/johanix/tdns/v2/cli   v0.0.0-20260611090745-44755a2166f9
github.com/johanix/tdns/v2/core  v0.0.0-20260611090745-44755a2166f9
github.com/johanix/tdns/v2/edns0 v0.0.0-20260611090745-44755a2166f9
replace github.com/miekg/dns => github.com/johanix/dns v0.0.0-20260608092609-2a28f8f1484d  # pre-OOTS fork tip
```

## Confirmed compile breakage vs tdns `main` (2026-07-21)

Built `tdns-mp/v2` against tdns `main` with local `replace` directives. Every
row below is a hard compile error today; the tdns-side attribution is best-effort
(from `git log -S` in the pin..main range).

| # | tdns-mp site | Symbol / API | What changed on tdns | tdns-side (approx) |
|---|---|---|---|---|
| 1 | build-wide | `dns.SVCBOots`, `dns.SVCBOotsEntry` | tdns `main` uses the OOTS SvcParam from the fork; our pinned `johanix/dns` (2026-06-08 tip) predates it | `3771371` "Bump johanix/dns pin to v1.1.72-johanix.2 for registered oots SvcParamKey" |
| 2 | `agent_setup.go:59` | `tdns.NormalizeAddresses` | now returns `[]string`; we assign it to `[]tdns.AclEntry` (`mp.Local.Notify`) — the Notify/ACL type changed | ACL / AclEntry refactor |
| 3 | `apihandler_keystore.go` | `KeyDB.DnssecKeyMgmt(...)` | gained a leading `context.Context` param: `(ctx, *Tx, KeystorePost)` | context-threading sweep (e.g. around `bfb8813`) |
| 4 | `apihandler_keystore.go`, `signer_keydb.go` | `KeyDB.KeystoreDnskeyCache` | field/method **removed** from `*tdns.KeyDB` (also breaks our `HsyncDB` mirror) | keystore refactor, e.g. `a9afee4` "ZSK rollover step 0" |
| 5 | `hsync_utils.go` | `tdns.SliceZone` | **removed / renamed** | zone-data refactor |
| 6 | `hsync_utils.go` | `MPZoneData.Owners` | our embedding of `tdns.ZoneData` broke — `Owners` field/accessor changed upstream | ZoneData refactor (`OwnerData` access) |
| 7 | `key_state_worker.go` | `Config.Kasp` | **removed** from `*tdns.Config` (KASP → dnssec policy restructure) | `491bb05` "per-role KSK/ZSK algorithm gating + config restructure" |
| 8 | `start_agent.go`, `start_auditor.go` | `Config.InitImrEngine(...)` | gained parameter(s) | IMR engine init signature change |
| 9 | `start_{agent,auditor,combiner,signer}.go` | `tdns.Notifier(...)` | gained parameter(s) | notifier signature change |

### Additionally: the XoT stack (not yet on `main`)

When tdns PRs **#314 / #316 / #318** (XoT / cert tooling / peers) land on `main`,
one more break arrives:

| tdns-mp site | Symbol | Change |
|---|---|---|
| `apirouter_sync.go:99` | `tdns.VerifyCertAgainstTlsaRR(tlsaRR, clientCert.Raw)` | signature changed `[]byte` → `*x509.Certificate`. Fix: pass `clientCert` (the `*x509.Certificate`) instead of `clientCert.Raw`. |

XoT Phase 0 assumed the only caller was dead commented code in tdns's own
`apiclient.go`; it missed that **tdns-mp's API TLS gate is a live caller**. So a
pin bump that includes the XoT stack is a hard compile failure until this
one-liner lands in tdns-mp.

## Why this keeps happening (the pattern)

tdns is under heavy, fast development (468 commits in ~6 weeks). The recurring
sources of drift:

- **DNSSEC policy restructure** — KASP config collapsed into `dnssec.policies`;
  per-role KSK/ZSK algorithm gating; keystore/rollover refactors (removed
  `KeystoreDnskeyCache`, changed `DnssecKeyMgmt`). This area churns the most.
- **Context threading** — `context.Context` being pushed through engine/keystore
  APIs (`DnssecKeyMgmt`, `InitImrEngine`, dynamic-zone provisioning).
- **Vocabulary / type changes** — transfer terminology (`primaries`/`upstreams`,
  `secondaries`/`downstreams`), ACL entries as `[]AclEntry`, `NormalizeAddresses`
  return type.
- **The `johanix/dns` fork** — tdns advances the fork tag for new SvcParamKeys
  (OOTS `SVCBOots`, OTS→OOTS rename) and the algorithm registry. This has bitten
  before: the fork was consolidated on tag `v1.1.72-johanix.1` and tdns repinned
  via tdns PR #280; it has since moved to `v1.1.72-johanix.2`. **A tdns pin bump
  almost always requires a matching `johanix/dns` fork bump in tdns-mp too.**
- **Engine wiring** — `InitImrEngine`, `Notifier`, `StartEngine` signatures.

There is a longer-term mitigation already discussed: consolidating tdns-mp's
multi-provider registry with tdns and reducing the surface tdns-mp reaches into
(see the April dependency docs). Until that lands, expect this drift to recur.

## Recommended handling of a tdns pin bump

1. **Never bump the tdns pin casually.** Schedule it; expect a compile-fix pass.
2. Bump `johanix/dns` (the `miekg/dns => johanix/dns` replace) in the **same**
   change — to at least `v1.1.72-johanix.2`.
3. Work the compile errors top-down (they cascade): fork symbols → keystore/DNSSEC
   APIs → engine init → the XoT `VerifyCertAgainstTlsaRR` one-liner.
4. Re-run the full `tdns-mp` regression suite; the drift is mostly signature-level
   but item 2 (`NormalizeAddresses` → `[]AclEntry`) and item 6 (`ZoneData.Owners`)
   are semantic and deserve a second look.
5. Update this doc with the new pin and any new drift found.

## How to regenerate this drift list

From `tdns-mp/v2`, with a local tdns checkout at `$T` (e.g. the tdns `main`
worktree) and the fork aligned to what tdns `main` uses:

```sh
cp go.mod /tmp/go.mod.bak
go mod edit \
  -replace github.com/johanix/tdns/v2=$T \
  -replace github.com/johanix/tdns/v2/cache=$T/cache \
  -replace github.com/johanix/tdns/v2/cli=$T/cli \
  -replace github.com/johanix/tdns/v2/core=$T/core \
  -replace github.com/johanix/tdns/v2/edns0=$T/edns0 \
  -replace github.com/miekg/dns=github.com/johanix/dns@v1.1.72-johanix.2
go build -mod=mod -gcflags=-e ./...      # every remaining error is real drift
git checkout go.mod go.sum               # revert — leave tdns-mp pristine
```

(GOROOT for this toolchain: `/opt/local/lib/go`.)
